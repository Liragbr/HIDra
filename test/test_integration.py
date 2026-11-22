"""Actual TLS on ephemeral loopback ports, ephemeral CA, and an in-memory HID sink."""
import hashlib
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from hidra.protocol import ProtocolError, RateLimiter, negotiate, sign
from server.c2_server import Config, Server, Session, parse_ducky
from test import pico_agent_sim as sim
from test.test_protocol import SECRET, TOKEN

ROOT = Path(__file__).resolve().parents[1]


class IntegrationFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="hidra-tests-")
        cls.certs = Path(cls.temp.name) / "certs"
        subprocess.run(["bash", str(ROOT / "gen_certs.sh"), str(cls.certs)],
                       check=True, capture_output=True)
        cls.other = Path(cls.temp.name) / "other"
        subprocess.run(["bash", str(ROOT / "gen_certs.sh"), str(cls.other)],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "req", "-new", "-key", str(cls.certs / "server.key"),
                        "-out", str(cls.certs / "expired.csr"), "-subj", "/CN=localhost"],
                       check=True, capture_output=True)
        ext = cls.certs / "expired.ext"
        ext.write_text("subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n")
        (cls.certs / "index").write_text("")
        (cls.certs / "serial").write_text("1000\n")
        cfg = cls.certs / "ca.cnf"
        cfg.write_text(f"[ca]\ndefault_ca=lab\n[lab]\ndatabase={cls.certs}/index\n"
                       f"serial={cls.certs}/serial\nnew_certs_dir={cls.certs}\n"
                       f"certificate={cls.certs}/ca.pem\nprivate_key={cls.certs}/ca.key\n"
                       "default_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n")
        subprocess.run(["openssl", "ca", "-batch", "-config", str(cfg),
                        "-in", str(cls.certs / "expired.csr"), "-startdate", "20000101000000Z",
                        "-enddate", "20010101000000Z", "-extfile", str(ext),
                        "-out", str(cls.certs / "expired.pem")], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.servers = []
        self.sockets = []
        self.threads = []
        self.thread_errors = []

    def tearDown(self):
        for conn in self.sockets:
            conn.close()
        for server, thread in self.servers:
            server.shutdown()
            thread.join(3)
            self.assertFalse(thread.is_alive(), "server thread did not stop")
        for thread in self.threads:
            thread.join(3)
            self.assertFalse(thread.is_alive(), "agent thread did not stop")
        self.assertEqual(self.thread_errors, [], "uncaught test worker exceptions")

    def config(self):
        config = Config()
        config.HOST, config.PORT = "127.0.0.1", 0
        config.TOKEN, config.HMAC_SECRET = TOKEN, SECRET
        config.CERT, config.KEY = str(self.certs / "server.pem"), str(self.certs / "server.key")
        config.TIMEOUT = 0.6
        return config

    def start(self, script=None, config=None):
        server = Server(config or self.config(), script)
        def serve():
            try:
                server.run()
            except BaseException as exc:
                self.thread_errors.append(type(exc).__name__)
        thread = threading.Thread(target=serve)
        thread.start()
        self.servers.append((server, thread))
        return server

    def agent_config(self, server):
        config = sim.Config()
        config.HOST, config.PORT = server.address
        config.TOKEN, config.HMAC_SECRET = TOKEN, SECRET
        config.CA_CERT = str(self.certs / "ca.pem")
        config.LAB_MODE, config.TIMEOUT = False, 1.5
        return config

    def connect(self, server, context=None, hostname="localhost"):
        config = self.agent_config(server)
        context = context or sim.build_tls_context(config)
        raw = socket.create_connection(server.address, timeout=1)
        try:
            conn = context.wrap_socket(raw, server_hostname=hostname)
        except BaseException:
            raw.close()
            raise
        self.sockets.append(conn)
        return conn

    def auth(self, server, token=TOKEN, action="auth"):
        conn = self.connect(server)
        proto = negotiate(conn, SECRET, "agent", 1)
        proto.send({"action": action, "token": token})
        return conn, proto, proto.recv()

    def run_agent(self, server, recorder=None, rate=None):
        conn = self.connect(server)
        results = []
        def agent():
            try:
                results.append(sim.run_session(conn, self.agent_config(server), recorder, rate))
            except (OSError, EOFError, ProtocolError) as exc:
                results.append(type(exc).__name__)
            except BaseException as exc:
                self.thread_errors.append(type(exc).__name__)
            finally:
                conn.close()
        thread = threading.Thread(target=agent)
        thread.start()
        self.threads.append(thread)
        return thread, results

    def session(self, server):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            sessions = server.snapshot()
            if sessions:
                return sessions[0][1]
            time.sleep(.005)
        self.fail("authenticated session not registered")


class IntegrationTests(IntegrationFixture):
    def test_tls13_valid_auth_and_socket_cleanup(self):
        server = self.start()
        conn, _, response = self.auth(server)
        self.assertEqual(conn.version(), "TLSv1.3")
        self.assertEqual(response, {"ok": True, "action": "ok"})
        server.shutdown()
        self.assertEqual(conn.recv(1), b"")

    def test_auth_invalid_token_action_and_type(self):
        server = self.start()
        for token, action in [("wrong", "auth"), (42, "auth"), (TOKEN, "ping")]:
            with self.subTest(action=action, token_type=type(token).__name__):
                conn, _, response = self.auth(server, token, action)
                self.assertEqual(response, {"ok": False, "error": "authentication failed"})
                self.assertEqual(conn.recv(1), b"")
                conn.close()

    def test_hmac_tampering_closes_auth_connection(self):
        server = self.start()
        conn = self.connect(server)
        proto = negotiate(conn, SECRET, "agent", 1)
        body = json.dumps({"action": "auth", "token": TOKEN}, separators=(",", ":"))
        bad = {"v": 2, "sid": proto.sid, "seq": 1, "body": body, "sig": "0" * 64}
        conn.sendall(json.dumps(bad).encode() + b'\n')
        self.assertEqual(conn.recv(1), b"")
        self.assertEqual(server.snapshot(), [])

    def test_replayed_auth_from_another_session_is_rejected(self):
        server = self.start()
        conn, old, _ = self.auth(server)
        conn.close()
        new_conn = self.connect(server)
        new = negotiate(new_conn, SECRET, "agent", 1)
        self.assertNotEqual(old.sid, new.sid)
        body = json.dumps({"action": "auth", "token": TOKEN}, separators=(",", ":"))
        env = {"v": 2, "sid": old.sid, "seq": 1, "body": body,
               "sig": sign(SECRET, "a2s", old.sid, 1, body)}
        new_conn.sendall(json.dumps(env).encode() + b'\n')
        self.assertEqual(new_conn.recv(1), b"")

    def test_wrong_ca_and_hostname(self):
        server = self.start()
        config = self.agent_config(server)
        config.CA_CERT = str(self.other / 'ca.pem')
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connect(server, sim.build_tls_context(config))
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connect(server, hostname="wrong.invalid")

    def test_expired_certificate(self):
        config = self.config()
        config.CERT = str(self.certs / 'expired.pem')
        server = self.start(config=config)
        with self.assertRaises(ssl.SSLCertVerificationError) as result:
            self.connect(server)
        self.assertEqual(result.exception.verify_code, 10)

    def test_tls12_rejected(self):
        server = self.start()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(str(self.certs / 'ca.pem'))
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
        with self.assertRaises(ssl.SSLError):
            self.connect(server, context)

    def test_script_exact_events_and_server_exits(self):
        commands = parse_ducky('STRING benign test\nENTER\nDELAY 10')
        server = self.start(commands)
        recorder = sim.Recorder()
        thread, results = self.run_agent(server, recorder)
        thread.join(2)
        self.servers[-1][1].join(2)
        self.assertEqual(results, [True])
        self.assertEqual(list(recorder.events), commands)
        self.assertTrue(server.script_success)
        self.assertFalse(self.servers[-1][1].is_alive())

    def test_rate_limit_exact_30_of_35_and_ping(self):
        server = self.start()
        recorder = sim.Recorder()
        self.run_agent(server, recorder)
        session = self.session(server)
        results = [session.request({"action": "type", "text": "x"}) for _ in range(35)]
        self.assertEqual([r["ok"] for r in results], [True] * 30 + [False] * 5)
        self.assertEqual(len(recorder.events), 30)
        self.assertEqual(session.request({"action": "ping"}), {"action": "pong", "ok": True})
        session.request({"action": "exit"})

    def test_script_stops_on_rejection(self):
        server = self.start([{"action": "type", "text": "x"}] * 35)
        recorder = sim.Recorder()
        thread, _ = self.run_agent(server, recorder)
        thread.join(2)
        self.assertFalse(server.script_success)
        self.assertEqual(len(recorder.events), 30)
        self.assertTrue(server.stop.wait(1))

    def test_concurrent_requests_have_single_transaction_owner(self):
        server = self.start()
        self.run_agent(server)
        session = self.session(server)
        results = []
        def request():
            try:
                results.append(session.request({"action": "ping"}))
            except BaseException as exc:
                self.thread_errors.append(type(exc).__name__)
        threads = [threading.Thread(target=request) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(2)
            self.assertFalse(thread.is_alive())
        self.assertEqual(results, [{"ok": True, "action": "pong"}] * 12)
        session.request({"action": "exit"})

    def test_stalled_handshake_does_not_block_next_client(self):
        server = self.start()
        stalled = socket.create_connection(server.address, timeout=2)
        self.sockets.append(stalled)
        conn, _, response = self.auth(server)
        self.assertTrue(response["ok"])
        self.assertEqual(stalled.recv(1), b"")
        conn.close()

    def test_auth_timeout(self):
        server = self.start()
        conn = self.connect(server)
        negotiate(conn, SECRET, "agent", 1)
        self.assertEqual(conn.recv(1), b"")
        self.assertEqual(server.snapshot(), [])

    def test_session_limit_and_recovery(self):
        config = self.config()
        config.MAX_CLIENTS = 1
        server = self.start(config=config)
        first = socket.create_connection(server.address, timeout=2)
        self.sockets.append(first)
        # Wait for the bounded slot to be taken, with an objective deadline.
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            with server.lock:
                if server.connections:
                    break
            time.sleep(.005)
        second = socket.create_connection(server.address, timeout=2)
        self.sockets.append(second)
        self.assertEqual(second.recv(1), b"")
        self.assertEqual(first.recv(1), b"")
        _, _, response = self.auth(server)
        self.assertTrue(response["ok"])

    def test_admission_rate_limit(self):
        server = self.start()
        server.admission = RateLimiter(1, 60)
        conn, _, response = self.auth(server)
        self.assertTrue(response["ok"])
        second = socket.create_connection(server.address, timeout=2)
        self.sockets.append(second)
        self.assertEqual(second.recv(1), b"")
        conn.close()

    def test_failed_connection_retries_with_delay_then_recovers(self):
        server = self.start([])
        config = self.agent_config(server)
        delays, attempts = [], []
        def connect(address, timeout):
            attempts.append(address)
            if len(attempts) < 3:
                raise ConnectionRefusedError("isolated fixture")
            return socket.create_connection(address, timeout=timeout)
        self.assertTrue(sim.run_client(config, connect=connect, sleep=delays.append, max_attempts=3))
        self.assertEqual(len(attempts), 3)
        self.assertEqual(len(delays), 2)
        self.assertTrue(all(1 <= d <= 2.4 for d in delays))

    def test_eof_retries_are_delayed_and_rate_state_survives(self):
        config = self.agent_config(self.start())
        delays, rates = [], []
        def session(conn, cfg, recorder, rate):
            rates.append(rate)
            if len(rates) == 1:
                self.assertTrue(rate.allow())
                raise EOFError()
            self.assertEqual(len(rate.timestamps), 1)
            return True
        with patch.object(sim, 'run_session', side_effect=session):
            self.assertTrue(sim.run_client(config, sleep=delays.append, max_attempts=2))
        self.assertEqual(len(delays), 1)
        self.assertIs(rates[0], rates[1])

    def test_malformed_command_and_signature_never_reach_sink(self):
        server = self.start()
        recorder = sim.Recorder()
        thread, results = self.run_agent(server, recorder)
        session = self.session(server)
        with session.lock:
            session.proto.send({"action": "type", "text": 42})
            self.assertFalse(session.proto.recv()["ok"])
            seq = session.proto.txseq
            body = '{"action":"type","text":"never recorded"}'
            bad = {"v": 2, "sid": session.proto.sid, "seq": seq, "body": body, "sig": '0' * 64}
            session.proto.framer.write(json.dumps(bad))
        thread.join(2)
        self.assertEqual(results, ['ProtocolError'])
        self.assertEqual(list(recorder.events), [])

    def test_response_timeout_closes_session(self):
        server = self.start()
        self.auth(server)
        session = self.session(server)
        with self.assertRaises(TimeoutError):
            session.request({"action": "ping"})
        self.assertTrue(session.closed)

    def test_certificate_generation_no_overwrite_and_private_permissions(self):
        before = hashlib.sha256((self.certs / 'ca.key').read_bytes()).digest()
        result = subprocess.run(['bash', str(ROOT / 'gen_certs.sh'), str(self.certs)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(before, hashlib.sha256((self.certs / 'ca.key').read_bytes()).digest())
        self.assertEqual((self.certs / 'server.key').stat().st_mode & 0o077, 0)

    def test_no_credentials_or_commands_in_logs(self):
        server = self.start()
        with self.assertLogs('hidra.server', level='WARNING') as logs:
            _, _, response = self.auth(server, token='private-fixture-must-not-appear')
            self.assertFalse(response['ok'])
        output = '\n'.join(logs.output)
        self.assertNotIn('private-fixture-must-not-appear', output)
        self.assertNotIn(TOKEN, output)
        self.assertNotIn(SECRET, output)

    def test_missing_and_identical_secrets_refuse_startup(self):
        for token, secret in [('', SECRET), (TOKEN, ''), (TOKEN, TOKEN)]:
            config = self.config()
            config.TOKEN, config.HMAC_SECRET = token, secret
            with self.assertRaises(ValueError):
                Server(config)

    def test_bad_response_schema_is_terminal(self):
        class FakeProto:
            def send(self, _):
                pass
            def recv(self):
                return {"ok": "true"}
        session = Session(FakeProto())
        with self.assertRaises(ProtocolError):
            session.request({"action": "ping"})
        self.assertTrue(session.closed)
