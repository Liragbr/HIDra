#!/usr/bin/env python3
"""Headless HIDra agent: records bounded events; never touches a keyboard or OS shell."""
import logging
import os
from pathlib import Path
import random
import socket
import ssl
import sys
import time
from collections import deque

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hidra.protocol import ProtocolError, RateLimiter, negotiate, validate_command, validate_secret

LOG = logging.getLogger("hidra.sim")


class Config:
    def __init__(self):
        self.HOST = os.environ.get("RUNNER_HOST", "127.0.0.1")
        self.PORT = int(os.environ.get("RUNNER_PORT", "9000"))
        self.TOKEN = os.environ.get("RUNNER_TOKEN", "")
        self.HMAC_SECRET = os.environ.get("RUNNER_HMAC_SECRET", "")
        self.CA_CERT = os.environ.get("RUNNER_CA_CERT", "ca.pem")
        self.LAB_MODE = os.environ.get("RUNNER_LAB_MODE", "0") == "1"
        self.TIMEOUT = 20.0


class Recorder:
    """Explicit simulation sink. Bounded history; ACK means accepted by this sink."""
    def __init__(self):
        self.events = deque(maxlen=1024)

    def execute(self, message):
        self.events.append(dict(message))


def build_tls_context(config):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    if config.LAB_MODE:
        LOG.warning("LAB MODE: server identity verification disabled")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.load_verify_locations(config.CA_CERT)
    return ctx


def run_session(conn, config, recorder=None, rate=None):
    recorder = recorder if recorder is not None else Recorder()
    rate = rate if rate is not None else RateLimiter()
    proto = negotiate(conn, config.HMAC_SECRET, "agent", config.TIMEOUT)
    proto.send({"action": "auth", "token": config.TOKEN})
    response = proto.recv()
    if response != {"ok": True, "action": "ok"}:
        return True  # Auth rejected: stop rather than retry credentials forever.
    while True:
        msg = proto.recv()
        try:
            validate_command(msg)
        except ProtocolError:
            proto.send({"ok": False, "error": "invalid command"})
            continue
        action = msg["action"]
        if action == "ping":
            proto.send({"ok": True, "action": "pong"})
        elif action in {"exit", "terminate"}:
            proto.send({"ok": True})
            return True
        elif not rate.allow():
            proto.send({"ok": False, "error": "rate limit exceeded"})
        else:
            recorder.execute(msg)
            proto.send({"ok": True})


def backoff_delay(attempt, random_value=None):
    base = min(60.0, 2.0 ** min(max(attempt, 0), 6))
    # Jitter does not change the next base and never exceeds the hard ceiling.
    # Non-cryptographic reconnect jitter; protocol nonces use secrets.token_hex.
    sample = random.random() if random_value is None else random_value  # nosec B311
    return max(1.0, min(60.0, base * (0.8 + 0.4 * sample)))


def run_client(config, *, stop=None, sleep=time.sleep, connect=socket.create_connection,
               max_attempts=None, recorder=None):
    validate_secret(config.TOKEN)
    validate_secret(config.HMAC_SECRET)
    context = build_tls_context(config)
    rate = RateLimiter()  # Persists across reconnects.
    attempt = 0
    while stop is None or not stop.is_set():
        try:
            with connect((config.HOST, config.PORT), timeout=config.TIMEOUT) as raw:
                with context.wrap_socket(raw, server_hostname=config.HOST) as conn:
                    if run_session(conn, config, recorder, rate):
                        return True
        except ssl.SSLCertVerificationError:
            LOG.error("server certificate rejected; stopping")
            return False
        except ProtocolError:
            LOG.error("protocol rejected; stopping")
            return False
        except (OSError, EOFError):
            LOG.warning("connection lost; retry scheduled")
        if max_attempts is not None and attempt + 1 >= max_attempts:
            return False
        delay = backoff_delay(attempt)
        if stop is not None:
            stop.wait(delay)
        else:
            sleep(delay)
        attempt += 1
    return False


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        return 0 if run_client(Config()) else 1
    except (OSError, ValueError):
        LOG.error("invalid simulator configuration")
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
