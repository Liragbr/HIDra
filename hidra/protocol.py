"""Protocol v2: TLS, mutual session nonces, directional HMAC and ordered frames."""
import hashlib
import hmac
import json
import re
import secrets
import socket
import threading
import time

MAX_FRAME = 2048  # Bytes before LF, on every implementation.
MAX_BODY = 768
MAX_TEXT = 256
MAX_SEQ = 2**31 - 1
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MODIFIERS = {"CTRL", "CONTROL", "SHIFT", "ALT", "WIN", "GUI"}
KEYS = {"ENTER", "ESC", "TAB", "SPACE", "DEL", "BACKSPACE", "HOME", "END",
        "PGUP", "PGDN", "UP", "DOWN", "LEFT", "RIGHT"} | {f"F{i}" for i in range(1, 13)}


class ProtocolError(ValueError):
    """Peer violated the protocol; close this connection, never resynchronize."""


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate field")
        result[key] = value
    return result


def loads(data):
    try:
        obj = json.loads(data, object_pairs_hook=_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(ProtocolError("constant")))
        if not isinstance(obj, dict) or len(obj) > 8:
            raise ProtocolError("object required")
        # Protocol deliberately excludes nested values and non-ASCII strings.
        for key, value in obj.items():
            if not isinstance(key, str) or not key.isascii() or len(key) > 16 or "\x00" in key:
                raise ProtocolError("invalid key")
            if type(value) not in (str, int, bool):
                raise ProtocolError("invalid field type")
            if type(value) is int and not 0 <= value <= MAX_SEQ:
                raise ProtocolError("integer range")
            if isinstance(value, str) and (not value.isascii() or '\x00' in value):
                raise ProtocolError("invalid string")
        return obj
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise ProtocolError("invalid JSON object") from exc


def dumps(obj):
    try:
        body = json.dumps(obj, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        loads(body)
        return body
    except (ValueError, TypeError, RecursionError) as exc:
        raise ProtocolError("cannot encode object") from exc


def validate_secret(secret):
    if (not isinstance(secret, str) or not 32 <= len(secret) <= 127
            or not all(33 <= ord(c) <= 126 for c in secret)
            or secret.startswith(("change_me", "your_"))):
        raise ValueError("secrets must be 32..127 printable ASCII characters, without spaces")


def ct_equal(a, b):
    return isinstance(a, str) and isinstance(b, str) and hmac.compare_digest(a.encode(), b.encode())


def sign(secret, direction, sid, seq, body):
    signed = f"HIDra/2\n{direction}\n{sid}\n{seq}\n{body}".encode("ascii")
    return hmac.new(secret.encode("ascii"), signed, hashlib.sha256).hexdigest()


def session_id(server_nonce, agent_nonce):
    return hashlib.sha256(f"HIDra/2\n{server_nonce}\n{agent_nonce}".encode("ascii")).hexdigest()


class Framer:
    def __init__(self, conn, timeout=10.0):
        if timeout <= 0:
            raise ValueError("positive timeout required")
        self.conn, self.timeout, self.buffer = conn, timeout, b""

    def read(self):
        deadline = time.monotonic() + self.timeout
        while True:
            if b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                if not line or len(line) > MAX_FRAME:
                    raise ProtocolError("frame length")
                return line
            if len(self.buffer) > MAX_FRAME:
                raise ProtocolError("frame length")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("frame deadline")
            self.conn.settimeout(remaining)
            chunk = self.conn.recv(min(1024, MAX_FRAME + 1 - len(self.buffer)))
            if not chunk:
                if self.buffer:
                    raise ProtocolError("truncated frame")
                raise EOFError("peer closed")
            self.buffer += chunk

    def write(self, line):
        data = line.encode("ascii")
        if not data or len(data) > MAX_FRAME or b"\n" in data:
            raise ProtocolError("frame length or separator")
        self.conn.settimeout(self.timeout)
        self.conn.sendall(data + b"\n")


class Proto:
    """One I/O owner. Server serializes complete request/response transactions."""
    def __init__(self, conn, secret, sid, role, timeout=10.0, framer=None):
        validate_secret(secret)
        if not HEX64.fullmatch(sid) or role not in ("server", "agent"):
            raise ValueError("session configuration")
        self.framer = framer or Framer(conn, timeout)
        self.secret, self.sid = secret, sid
        self.txdir = "s2a" if role == "server" else "a2s"
        self.rxdir = "a2s" if role == "server" else "s2a"
        self.txseq = self.rxseq = 1
        self.failed = False

    def send(self, payload):
        if self.failed or self.txseq > MAX_SEQ:
            raise ProtocolError("closed or exhausted session")
        body = dumps(payload)
        if len(body) > MAX_BODY:
            raise ProtocolError("body length")
        env = {"v": 2, "sid": self.sid, "seq": self.txseq, "body": body,
               "sig": sign(self.secret, self.txdir, self.sid, self.txseq, body)}
        try:
            self.framer.write(dumps(env))
        except (OSError, ValueError):
            self.failed = True
            raise
        self.txseq += 1

    def recv(self):
        if self.failed:
            raise ProtocolError("closed session")
        try:
            env = loads(self.framer.read())
            if (set(env) != {"v", "sid", "seq", "body", "sig"}
                    or type(env["v"]) is not int or env["v"] != 2
                    or type(env["seq"]) is not int or env["seq"] != self.rxseq
                    or self.rxseq > MAX_SEQ or env["sid"] != self.sid
                    or not isinstance(env["body"], str) or len(env["body"]) > MAX_BODY
                    or not isinstance(env["sig"], str) or not HEX64.fullmatch(env["sig"])):
                raise ProtocolError("envelope fields")
            expected = sign(self.secret, self.rxdir, self.sid, self.rxseq, env["body"])
            if not hmac.compare_digest(expected, env["sig"]):
                raise ProtocolError("signature")
            result = loads(env["body"])
            self.rxseq += 1
            return result
        except (OSError, EOFError, ValueError):
            self.failed = True
            raise


def negotiate(conn, secret, role, timeout=10.0):
    """Nonces travel inside verified TLS. Neither preface can carry a command."""
    validate_secret(secret)
    framer = Framer(conn, timeout)
    own = secrets.token_hex(32)
    if role == "server":
        framer.write(dumps({"challenge": own}))
        peer = loads(framer.read())
        if set(peer) != {"nonce"} or not isinstance(peer["nonce"], str) or not HEX64.fullmatch(peer["nonce"]):
            raise ProtocolError("nonce")
        sid = session_id(own, peer["nonce"])
    elif role == "agent":
        peer = loads(framer.read())
        if set(peer) != {"challenge"} or not isinstance(peer["challenge"], str) or not HEX64.fullmatch(peer["challenge"]):
            raise ProtocolError("challenge")
        framer.write(dumps({"nonce": own}))
        sid = session_id(peer["challenge"], own)
    else:
        raise ValueError("role")
    return Proto(conn, secret, sid, role, timeout, framer)


def validate_command(msg):
    if not isinstance(msg, dict) or not isinstance(msg.get("action"), str):
        raise ProtocolError("action required")
    action = msg["action"]
    field = {"type": "text", "key": "keys", "delay": "text"}.get(action)
    if action not in {"type", "key", "delay", "ping", "exit", "terminate"}:
        raise ProtocolError("unknown action")
    if set(msg) != ({"action", field} if field else {"action"}):
        raise ProtocolError("command fields")
    if field and not isinstance(msg[field], str):
        raise ProtocolError("string required")
    if action == "type":
        text = msg[field]
        if not 1 <= len(text) <= MAX_TEXT or not all(c in '\n\t' or 32 <= ord(c) <= 126 for c in text):
            raise ProtocolError("unsupported text")
    elif action == "delay":
        if not re.fullmatch(r"0|[1-9][0-9]{0,3}", msg[field]) or int(msg[field]) > 5000:
            raise ProtocolError("delay range")
    elif action == "key":
        tokens = msg[field].split(" ")
        if len(msg[field]) > 63 or not tokens or any(not t for t in tokens):
            raise ProtocolError("key syntax")
        normal = [t for t in tokens if t not in MODIFIERS]
        if len(normal) != 1 or len(tokens) != len(set(tokens)):
            raise ProtocolError("one key required")
        if any(t not in KEYS and not (len(t) == 1 and t.isascii() and t.isalnum()) for t in normal):
            raise ProtocolError("unsupported key")
    return msg


class RateLimiter:
    def __init__(self, limit=30, window=60.0, clock=time.monotonic):
        if limit <= 0 or window <= 0:
            raise ValueError("positive rate limits required")
        self.limit, self.window, self.clock = limit, window, clock
        self.timestamps = []
        self.lock = threading.Lock()

    def allow(self):
        with self.lock:
            now = self.clock()
            self.timestamps = [t for t in self.timestamps if now - t < self.window]
            if len(self.timestamps) >= self.limit:
                return False
            self.timestamps.append(now)
            return True


def close_socket(conn):
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    finally:
        conn.close()
