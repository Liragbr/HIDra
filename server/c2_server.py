#!/usr/bin/env python3
"""Bounded TLS 1.3 laboratory server. Run from the repository root."""
import argparse
import logging
import os
from pathlib import Path
import socket
import ssl
import sys
import threading

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hidra.protocol import (ProtocolError, RateLimiter, close_socket, ct_equal,
                            negotiate, validate_command, validate_secret)

LOG = logging.getLogger("hidra.server")


class Config:
    def __init__(self):
        self.HOST = os.environ.get("RUNNER_HOST", "127.0.0.1")
        self.PORT = int(os.environ.get("RUNNER_PORT", "9000"))
        self.TOKEN = os.environ.get("RUNNER_TOKEN", "")
        self.HMAC_SECRET = os.environ.get("RUNNER_HMAC_SECRET", "")
        self.CERT = os.environ.get("RUNNER_CERT", "server.pem")
        self.KEY = os.environ.get("RUNNER_KEY", "server.key")
        self.TIMEOUT = 10.0
        self.MAX_CLIENTS = 8

    def validate(self):
        validate_secret(self.TOKEN)
        validate_secret(self.HMAC_SECRET)
        if ct_equal(self.TOKEN, self.HMAC_SECRET):
            raise ValueError("token and HMAC key must differ")
        if not 0 <= self.PORT <= 65535 or not 0 < self.MAX_CLIENTS <= 64 or not 0 < self.TIMEOUT <= 120:
            raise ValueError("invalid server limits")


def make_type(text):
    return validate_command({"action": "type", "text": text})


def make_key(combo):
    return validate_command({"action": "key", "keys": combo})


def make_delay(ms):
    return validate_command({"action": "delay", "text": str(ms)})


def parse_ducky(script):
    """Reject the whole script on any unsupported line, before sending anything."""
    payloads = []
    for number, raw in enumerate(script.splitlines(), 1):
        line = raw.lstrip()
        command, _, arg = line.partition(" ")
        command = command.upper()
        if not line or command == "REM":
            continue
        try:
            if command == "STRING":
                payload = make_type(arg)
            elif command == "DELAY":
                payload = validate_command({"action": "delay", "text": arg.strip()})
            else:
                # Normalize names, keep single letters lower case to avoid implicit SHIFT.
                tokens = line.split()
                payload = make_key(" ".join(t.lower() if len(t) == 1 else t.upper() for t in tokens))
        except ProtocolError as exc:
            raise ValueError(f"invalid script line {number}") from exc
        payloads.append(payload)
        if len(payloads) > 1000:
            raise ValueError("script exceeds 1000 commands")
    return payloads


def build_tls_context(config):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(config.CERT, config.KEY)
    return ctx


class Session:
    def __init__(self, proto):
        self.proto = proto
        self.lock = threading.Lock()
        self.closed = False

    def request(self, payload):
        validate_command(payload)
        with self.lock:
            if self.closed:
                raise EOFError("session closed")
            try:
                self.proto.send(payload)
                response = self.proto.recv()
                if type(response.get("ok")) is not bool:
                    raise ProtocolError("response status")
                if payload["action"] == "ping" and response != {"ok": True, "action": "pong"}:
                    raise ProtocolError("unexpected pong")
                if payload["action"] in {"exit", "terminate"}:
                    self.closed = True
                return response
            except (OSError, EOFError, ValueError):
                self.closed = True
                raise


class Server:
    def __init__(self, config, script_payloads=None):
        config.validate()
        self.config, self.script = config, script_payloads
        if script_payloads is not None:
            for item in script_payloads:
                validate_command(item)
        self.context = build_tls_context(config)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.sessions, self.connections, self.workers = {}, set(), set()
        self.slots = threading.BoundedSemaphore(config.MAX_CLIENTS)
        self.admission = RateLimiter(60, 60)
        self.script_claimed = False
        self.script_success = False
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind((config.HOST, config.PORT))
            self.listener.listen(config.MAX_CLIENTS)
            self.listener.settimeout(0.2)
        except OSError:
            self.listener.close()
            raise
        self.address = self.listener.getsockname()

    def snapshot(self):
        with self.lock:
            return list(self.sessions.items())

    def run(self):
        LOG.info("listening on %s:%d (TLS 1.3)", *self.address)
        try:
            while not self.stop.is_set():
                try:
                    raw, addr = self.listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self.stop.is_set():
                        break
                    raise
                if not self.admission.allow() or not self.slots.acquire(blocking=False):
                    raw.close()
                    LOG.warning("connection admission rejected")
                    continue
                worker = threading.Thread(target=self._handle, args=(raw, addr), daemon=True)
                with self.lock:
                    self.connections.add(raw)
                    self.workers.add(worker)
                try:
                    worker.start()
                except RuntimeError:
                    with self.lock:
                        self.connections.discard(raw)
                        self.workers.discard(worker)
                    raw.close()
                    self.slots.release()
                    raise
        finally:
            self.shutdown()
            with self.lock:
                workers = list(self.workers)
            for worker in workers:
                worker.join(self.config.TIMEOUT + 1)

    def _handle(self, raw, addr):
        conn = raw
        claimed = False
        try:
            raw.settimeout(self.config.TIMEOUT)
            conn = self.context.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
            with self.lock:
                self.connections.discard(raw)
                self.connections.add(conn)
            conn.do_handshake()
            proto = negotiate(conn, self.config.HMAC_SECRET, "server", self.config.TIMEOUT)
            msg = proto.recv()
            if (set(msg) != {"action", "token"} or msg.get("action") != "auth"
                    or not ct_equal(msg.get("token"), self.config.TOKEN)):
                proto.send({"ok": False, "error": "authentication failed"})
                LOG.warning("authentication rejected")
                return
            if self.script is not None:
                with self.lock:
                    if self.script_claimed:
                        return
                    self.script_claimed = claimed = True
            proto.send({"ok": True, "action": "ok"})
            session = Session(proto)
            if self.script is not None:
                for payload in self.script:
                    if not session.request(payload)["ok"]:
                        LOG.warning("script stopped on rejected command")
                        return
                self.script_success = session.request({"action": "exit"})["ok"]
                return
            with self.lock:
                self.sessions[addr] = session
            while not self.stop.wait(10):
                if session.closed:
                    break
                session.request({"action": "ping"})
        except ssl.SSLError as exc:
            LOG.warning("TLS failure: %s", exc.reason)
        except (OSError, EOFError, ValueError):
            LOG.warning("session closed: transport, authentication or protocol failure")
        finally:
            with self.lock:
                self.sessions.pop(addr, None)
                self.connections.discard(conn)
                self.connections.discard(raw)
                self.workers.discard(threading.current_thread())
            close_socket(conn)
            self.slots.release()
            if claimed:
                self.stop.set()

    def shutdown(self):
        self.stop.set()
        self.listener.close()
        with self.lock:
            connections = list(self.connections)
        for conn in connections:
            close_socket(conn)


def cli_loop(server):
    active = None
    print("HIDra: list | use N | type TEXT | key COMBO | delay MS | ping | script FILE | exit | terminate | quit")
    while not server.stop.is_set():
        try:
            command, _, arg = input("hidra> ").partition(" ")
            if command in {"quit", "q"}:
                return
            if command == "list":
                for index, (addr, _) in enumerate(server.snapshot()):
                    print(index, addr)
                continue
            if command == "use":
                index = int(arg)
                if index < 0:
                    raise ValueError("negative index")
                active = server.snapshot()[index][1]
                continue
            if not active:
                print("select an agent with use N")
                continue
            if command == "script":
                payloads = parse_ducky(Path(arg).read_text(encoding="utf-8"))
            elif command == "type":
                payloads = [make_type(arg)]
            elif command == "key":
                payloads = [make_key(arg)]
            elif command == "delay":
                payloads = [make_delay(int(arg))]
            else:
                payloads = [validate_command({"action": command})]
            for payload in payloads:
                response = active.request(payload)
                print("accepted" if response["ok"] else "rejected; script stopped")
                if not response["ok"]:
                    break
        except (EOFError, KeyboardInterrupt):
            return
        except (OSError, ValueError, IndexError):
            print("invalid input or disconnected session")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--script", help="run once on the first authenticated agent, then exit")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        script = parse_ducky(Path(args.script).read_text(encoding="utf-8")) if args.script else None
        server = Server(Config(), script)
        if script is not None:
            try:
                server.run()
            except KeyboardInterrupt:
                server.shutdown()
            return 0 if server.script_success else 1
        thread = threading.Thread(target=server.run)
        thread.start()
        try:
            cli_loop(server)
        finally:
            server.shutdown()
            thread.join()
        return 0
    except (OSError, ValueError):
        LOG.error("startup failed: check credentials, certificate and bind configuration")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
