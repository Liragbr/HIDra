#!/usr/bin/env python3
"""
pico_agent_sim.py — Simulador do agente Pico W para ambiente de teste
Roda no Windows Host e simula o firmware do Pico W.

Substitui:
  - USB HID        → pyautogui.typewrite() / pyautogui.hotkey()
  - Wi-Fi + mbedTLS → ssl.SSLContext (Python stdlib)
  - Ring buffer     → fila simples (threading.Queue)
  - Reconexão      → loop com backoff exponencial + jitter

Cobre todos os 4 cenários de teste:
  [T1] Protocolo TLS + HMAC funcionando
  [T2] Keystroke injection chegando no alvo
  [T3] Script DuckyScript sendo executado
  [T4] Rate limiting e reconexão com backoff

Instalação:
  pip install pyautogui

Uso:
  set RUNNER_HOST=192.168.56.101
  set RUNNER_PORT=9000
  set RUNNER_TOKEN=seu_token_aqui
  set RUNNER_HMAC_SECRET=seu_hmac_secret
  set RUNNER_CA_CERT=ca.pem          (ou set RUNNER_LAB_MODE=1)
  python pico_agent_sim.py

Variáveis opcionais:
  RUNNER_LAB_MODE=1   → desabilita verificação de cert TLS (lab only)
  SIM_DELAY=0.05      → delay em segundos entre teclas (padrão: 50ms)
  SIM_FOCUS_DELAY=0.3 → pausa antes de injetar (aguarda foco na janela)
"""

import hashlib
import hmac as hmac_mod
import json
import os
import queue
import random
import socket
import ssl
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional

# pyautogui para injeção de teclas
try:
    import pyautogui
    pyautogui.FAILSAFE = True   # mover mouse para canto superior esquerdo aborta
    pyautogui.PAUSE    = 0.0    # controlaremos o delay manualmente
except ImportError:
    print("[ERRO] Instale pyautogui:  pip install pyautogui")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════
# §1  Configuração
# ═══════════════════════════════════════════════════════════════════

class Config:
    HOST        = os.environ.get("RUNNER_HOST",        "192.168.56.101")
    PORT        = int(os.environ.get("RUNNER_PORT",    "9000"))
    TOKEN       = os.environ.get("RUNNER_TOKEN",       "")
    HMAC_SECRET = os.environ.get("RUNNER_HMAC_SECRET", "")
    CA_CERT     = os.environ.get("RUNNER_CA_CERT",     "ca.pem")
    LAB_MODE    = os.environ.get("RUNNER_LAB_MODE",    "0") == "1"

    # Simulador
    KEY_DELAY   = float(os.environ.get("SIM_DELAY",       "0.05"))
    FOCUS_DELAY = float(os.environ.get("SIM_FOCUS_DELAY", "0.3"))

    # Rate limit (espelha o firmware)
    RATE_LIMIT  = 30
    RATE_WINDOW = 60.0

    # Backoff
    MAX_BACKOFF = 60.0
    JITTER      = 0.3


# ═══════════════════════════════════════════════════════════════════
# §2  Logging
# ═══════════════════════════════════════════════════════════════════

def log(lvl: str, msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    print(f"{ts} [{lvl}] {msg}", flush=True)

def info(m): log("INFO", m)
def warn(m): log("WARN", m)
def crit(m): log("CRIT", m)


# ═══════════════════════════════════════════════════════════════════
# §3  Crypto — idêntico ao servidor / firmware
# ═══════════════════════════════════════════════════════════════════

def hmac_sign(secret: str, msg: str) -> str:
    return hmac_mod.new(
        secret.encode(), msg.encode(), hashlib.sha256
    ).hexdigest()

def ct_equal(a: str, b: str) -> bool:
    """[SEC-3] Constant-time compare"""
    return hmac_mod.compare_digest(a, b)


# ═══════════════════════════════════════════════════════════════════
# §4  Rate limiter  [T4]
# ═══════════════════════════════════════════════════════════════════

class RateLimiter:
    def __init__(self, limit: int, window: float):
        self._limit  = limit
        self._window = window
        self._ts: list[float] = []
        self._lock = threading.Lock()

    def allow(self) -> bool:
        now = time.monotonic()
        with self._lock:
            self._ts = [t for t in self._ts if now - t < self._window]
            if len(self._ts) >= self._limit:
                return False
            self._ts.append(now)
            return True

    def remaining(self) -> int:
        now = time.monotonic()
        with self._lock:
            active = [t for t in self._ts if now - t < self._window]
            return max(0, self._limit - len(active))


# ═══════════════════════════════════════════════════════════════════
# §5  Protocolo JSON com envelope HMAC  [T1]
# ═══════════════════════════════════════════════════════════════════

class Proto:
    """
    Lê/escreve mensagens JSON sobre TLS.
    Formato do envelope:
      {"body": "<json_string>", "sig": "<hmac_hex>"}
    """

    MAX_RECV = 64 * 1024

    def __init__(self, conn: ssl.SSLSocket):
        self._conn = conn
        self._buf  = b""

    def send(self, payload: dict) -> None:
        body = json.dumps(payload, separators=(',', ':'))
        sig  = hmac_sign(Config.HMAC_SECRET, body) if Config.HMAC_SECRET else ""
        env  = json.dumps({"body": body, "sig": sig}, separators=(',', ':'))
        self._conn.sendall((env + "\n").encode())

    def recv(self) -> Optional[dict]:
        """Recebe uma linha, verifica HMAC, retorna dict ou None."""
        while b"\n" not in self._buf:
            if len(self._buf) >= self.MAX_RECV:
                warn("recv overflow")
                return None
            try:
                chunk = self._conn.recv(4096)
            except (OSError, ssl.SSLError) as e:
                warn(f"recv error: {e}")
                return None
            if not chunk:
                return None
            self._buf += chunk

        line, self._buf = self._buf.split(b"\n", 1)
        line = line.rstrip(b"\r")

        try:
            env  = json.loads(line)
            body = env["body"]
            sig  = env.get("sig", "")
        except (json.JSONDecodeError, KeyError):
            warn("envelope malformado")
            return {"action": "invalid"}

        # [T1] Verifica HMAC antes de processar
        if Config.HMAC_SECRET:
            expected = hmac_sign(Config.HMAC_SECRET, body)
            if not ct_equal(expected, sig):
                warn("[T1] HMAC inválido — mensagem rejeitada")
                return {"action": "invalid", "error": "hmac mismatch"}

        try:
            parsed = json.loads(body)
            # Log [T1] de verificação bem-sucedida
            action = parsed.get("action", "?")
            info(f"[T1] ✓ HMAC OK  action={action!r}  sig={sig[:16]}…")
            return parsed
        except json.JSONDecodeError:
            return {"action": "invalid"}


# ═══════════════════════════════════════════════════════════════════
# §6  Mapa de teclas especiais para pyautogui  [T2]
# ═══════════════════════════════════════════════════════════════════

# Traduz tokens do protocolo → nomes pyautogui
_MODIFIER_MAP = {
    "CTRL":    "ctrl",
    "CONTROL": "ctrl",
    "SHIFT":   "shift",
    "ALT":     "alt",
    "WIN":     "win",
    "GUI":     "win",
}

_KEY_MAP = {
    "ENTER":     "enter",
    "ESC":       "esc",
    "TAB":       "tab",
    "SPACE":     "space",
    "DEL":       "delete",
    "BACKSPACE": "backspace",
    "HOME":      "home",
    "END":       "end",
    "PGUP":      "pageup",
    "PGDN":      "pagedown",
    "UP":        "up",
    "DOWN":      "down",
    "LEFT":      "left",
    "RIGHT":     "right",
    **{f"F{i}": f"f{i}" for i in range(1, 13)},
}


# ═══════════════════════════════════════════════════════════════════
# §7  Injetor de keystrokes via pyautogui  [T2]
# ═══════════════════════════════════════════════════════════════════

class KeyInjector:
    """
    Simula o que o firmware faz via USB HID:
      type  → pyautogui.write() (caractere por caractere)
      key   → pyautogui.hotkey() (combos)
      delay → time.sleep()
    """

    def __init__(self):
        self._lock = threading.Lock()

    def inject_type(self, text: str) -> None:
        """[T2] Injeta string de texto caractere por caractere."""
        info(f"[T2] inject_type → {text!r}")
        # Pausa para garantir que a janela alvo tem foco
        time.sleep(Config.FOCUS_DELAY)
        with self._lock:
            for ch in text:
                if ch == '\n':
                    pyautogui.press('enter')
                elif ch == '\t':
                    pyautogui.press('tab')
                else:
                    # typewrite não suporta todos os chars; write é mais robusto
                    pyautogui.write(ch, interval=0)
                time.sleep(Config.KEY_DELAY)

    def inject_key(self, combo: str) -> None:
        """
        [T2] Injeta combo de teclas.
        Exemplos: 'WIN r', 'CTRL ALT DEL', 'SHIFT F10'
        """
        info(f"[T2] inject_key  → {combo!r}")
        tokens   = combo.upper().split()
        keys_pg  = []   # lista de nomes pyautogui

        for tok in tokens:
            if tok in _MODIFIER_MAP:
                keys_pg.append(_MODIFIER_MAP[tok])
            elif tok in _KEY_MAP:
                keys_pg.append(_KEY_MAP[tok])
            elif len(tok) == 1:
                keys_pg.append(tok.lower())
            else:
                warn(f"[T2] token desconhecido ignorado: {tok!r}")

        if not keys_pg:
            return

        time.sleep(Config.FOCUS_DELAY)
        with self._lock:
            pyautogui.hotkey(*keys_pg)
            time.sleep(Config.KEY_DELAY)

    def inject_delay(self, ms: int) -> None:
        """[T2] Pausa no lado do agente (emula delay do firmware)."""
        ms = min(ms, 5000)
        info(f"[T2] delay       → {ms} ms")
        time.sleep(ms / 1000.0)


# ═══════════════════════════════════════════════════════════════════
# §8  Handler de sessão  [T1] [T2] [T3] [T4]
# ═══════════════════════════════════════════════════════════════════

def run_session(conn: ssl.SSLSocket) -> bool:
    """
    Roda uma sessão completa.
    Retorna True  → desconexão limpa (sem reconectar)
    Retorna False → erro de rede (reconectar com backoff)
    """
    proto    = Proto(conn)
    injector = KeyInjector()
    rate     = RateLimiter(Config.RATE_LIMIT, Config.RATE_WINDOW)

    # ── Autenticação  [T1] ──────────────────────────────────────────
    info("[T1] enviando auth…")
    proto.send({"action": "auth", "token": Config.TOKEN})

    resp = proto.recv()
    if not resp:
        warn("[T1] sem resposta ao auth")
        return False

    if not resp.get("ok"):
        crit(f"[T1] auth falhou: {resp.get('error', '?')}")
        return True   # não tentar reconectar — token errado

    info("[T1] ✓ autenticado")

    # ── Loop de comandos ────────────────────────────────────────────
    while True:
        msg = proto.recv()
        if not msg:
            warn("conexão perdida")
            return False

        action = msg.get("action", "")

        # Envelope corrompido / HMAC falhou
        if action == "invalid":
            warn(f"mensagem inválida: {msg.get('error', '?')}")
            continue

        # Keepalive
        if action == "ping":
            proto.send({"action": "pong", "ok": True})
            continue

        # ── Payloads HID  [T2] [T3] ───────────────────────────────
        if action in ("type", "key", "delay"):

            # [T4] Verifica rate limit
            if not rate.allow():
                remaining = rate.remaining()
                warn(f"[T4] rate limit atingido — {remaining} slots restantes")
                proto.send({"ok": False, "error": "rate limit exceeded"})
                continue

            info(f"[T4] rate OK — {rate.remaining()} slots restantes após este")

            try:
                if action == "type":
                    # [T3] DuckyScript STRING → inject_type
                    injector.inject_type(msg.get("text", ""))

                elif action == "key":
                    # [T3] DuckyScript GUI/CTRL/SHIFT → inject_key
                    injector.inject_key(msg.get("keys", ""))

                elif action == "delay":
                    # [T3] DuckyScript DELAY → inject_delay
                    injector.inject_delay(int(msg.get("text", "0")))

                proto.send({"ok": True})

            except Exception as exc:
                warn(f"erro ao injetar: {exc}")
                proto.send({"ok": False, "error": str(exc)})

        elif action == "exit":
            proto.send({"ok": True, "message": "bye"})
            info("sessão encerrada pelo servidor")
            return True

        elif action == "terminate":
            proto.send({"ok": True, "message": "terminating"})
            info("[T4] terminate recebido — simulador encerrado")
            sys.exit(0)

        else:
            warn(f"action desconhecida: {action!r}")
            proto.send({"ok": False, "error": f"unknown action: {action}"})


# ═══════════════════════════════════════════════════════════════════
# §9  TLS client  [T1]
# ═══════════════════════════════════════════════════════════════════

def build_tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    if Config.LAB_MODE:
        warn("[T1] RUNNER_LAB_MODE=1 — verificação de cert DESLIGADA (lab only)")
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    else:
        if not os.path.isfile(Config.CA_CERT):
            crit(f"[T1] CA cert não encontrado: {Config.CA_CERT}")
            crit("     Execute gen_certs.sh e copie ca.pem para esta pasta")
            crit("     OU defina RUNNER_LAB_MODE=1 para pular verificação")
            sys.exit(1)
        ctx.load_verify_locations(Config.CA_CERT)
        ctx.verify_mode    = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        info(f"[T1] TLS 1.3 com CA cert: {Config.CA_CERT}")

    return ctx


# ═══════════════════════════════════════════════════════════════════
# §10  Loop principal com backoff exponencial  [T4]
# ═══════════════════════════════════════════════════════════════════

def main() -> None:
    if not Config.TOKEN:
        crit("RUNNER_TOKEN não definido")
        sys.exit(1)
    if not Config.HMAC_SECRET:
        warn("RUNNER_HMAC_SECRET não definido — integridade desabilitada")
    if Config.LAB_MODE:
        warn("Modo lab ativo — NÃO usar em produção")

    tls_ctx = build_tls_context()
    backoff = 1.0

    info(f"simulador do Pico W iniciado → {Config.HOST}:{Config.PORT}")
    info(f"injeção de teclas via pyautogui  delay={Config.KEY_DELAY}s")
    info("dica: mantenha o Notepad (ou qualquer janela) em foco no alvo")
    print()

    while True:
        info(f"[T4] conectando a {Config.HOST}:{Config.PORT}…")
        try:
            raw = socket.create_connection((Config.HOST, Config.PORT), timeout=10)
            tls = tls_ctx.wrap_socket(raw, server_hostname=Config.HOST)
            info(f"[T1] TLS handshake OK  proto={tls.version()}  "
                 f"cipher={tls.cipher()[0]}")

            clean_exit = run_session(tls)
            tls.close()

            if clean_exit:
                info("[T4] desconexão limpa — não reconectando")
                break

            # Reconectar com backoff
            backoff = 1.0

        except (OSError, ssl.SSLError, ConnectionRefusedError) as exc:
            jitter  = backoff * Config.JITTER * (random.random() * 2 - 1)
            delay   = max(1.0, min(backoff + jitter, Config.MAX_BACKOFF))
            warn(f"[T4] erro de conexão: {exc}")
            warn(f"[T4] reconectando em {delay:.1f}s  (backoff={backoff:.0f}s)")
            time.sleep(delay)
            backoff = min(backoff * 2, Config.MAX_BACKOFF)

        except KeyboardInterrupt:
            info("interrompido pelo usuário")
            break


if __name__ == "__main__":
    main()
