import json
import socket
import threading
import time
import unittest

from hidra.protocol import (MAX_BODY, MAX_FRAME, MAX_SEQ, Framer, Proto, ProtocolError,
                            RateLimiter, dumps, loads, session_id, sign, validate_command,
                            validate_secret)
from server.c2_server import parse_ducky
from test.pico_agent_sim import backoff_delay

SECRET = "fixture-hmac-" + "a" * 40
TOKEN = "fixture-token-" + "b" * 40
SID = "1" * 64


class MemorySocket:
    def __init__(self, data=b"", fragment=1024):
        self.data, self.sent, self.fragment = data, b"", fragment

    def recv(self, size):
        size = min(size, self.fragment)
        chunk, self.data = self.data[:size], self.data[size:]
        return chunk

    def sendall(self, data):
        self.sent += data

    def settimeout(self, timeout):
        self.timeout = timeout


def frame(body='{"action":"ping"}', seq=1, sid=SID, direction="s2a", **overrides):
    env = {"v": 2, "sid": sid, "seq": seq, "body": body,
           "sig": sign(SECRET, direction, sid, seq, body)}
    env.update(overrides)
    return json.dumps(env, separators=(",", ":")).encode() + b"\n"


class ProtocolTests(unittest.TestCase):
    def read(self, data, **kw):
        return Proto(MemorySocket(data, **kw), SECRET, SID, "agent").recv()

    def test_round_trip_escaping_fragmented(self):
        obj = {"action": "type", "text": 'quote " slash \\ tab\t newline\n'}
        sender = MemorySocket()
        Proto(sender, SECRET, SID, "server").send(obj)
        self.assertEqual(self.read(sender.sent, fragment=1), obj)

    def test_coalesced_frames(self):
        proto = Proto(MemorySocket(frame() + frame(seq=2)), SECRET, SID, "agent")
        self.assertEqual(proto.recv(), {"action": "ping"})
        self.assertEqual(proto.recv(), {"action": "ping"})

    def test_tampered_signature_body_direction_session(self):
        for data in [frame(sig="0" * 64), frame(sig="a" * 63), frame(sig="A" * 64),
                     frame(direction="a2s"), frame(sid="2" * 64),
                     frame().replace(b'ping', b'exit')]:
            with self.subTest(data=data[:30]), self.assertRaises(ProtocolError):
                self.read(data)

    def test_replay_reorder_and_exhaustion(self):
        proto = Proto(MemorySocket(frame() * 2), SECRET, SID, "agent")
        proto.recv()
        with self.assertRaises(ProtocolError):
            proto.recv()
        for seq in (0, 2, MAX_SEQ + 1):
            with self.subTest(seq=seq), self.assertRaises(ProtocolError):
                self.read(frame(seq=seq))
        proto = Proto(MemorySocket(), SECRET, SID, "server")
        proto.txseq = MAX_SEQ + 1
        with self.assertRaises(ProtocolError):
            proto.send({"action": "ping"})

    def test_terminal_error_cannot_resynchronize(self):
        proto = Proto(MemorySocket(b"[]\n" + frame()), SECRET, SID, "agent")
        for _ in range(2):
            with self.assertRaises(ProtocolError):
                proto.recv()

    def test_invalid_envelope_types_and_fields(self):
        for value in [[], None, 1, "x", {"body": 42}, {"v": 2}]:
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                self.read(json.dumps(value).encode() + b"\n")
        for changes in [{"sig": 1}, {"body": []}, {"seq": True}, {"v": True},
                        {"seq": "1"}, {"extra": 1}]:
            with self.subTest(changes=changes), self.assertRaises(ProtocolError):
                self.read(frame(**changes))

    def test_malformed_duplicate_nested_and_non_ascii(self):
        invalid = ['{"a":1,"a":2}', '{"a":{}}', '{"a":[]}', '{"a":null}',
                   '{"a":NaN}', '{"a":Infinity}', '{"a":-1}', '{"a":1.0}',
                   '{"a":01}', '{"a":"\\u0000"}', '{"a":"á"}', '{}{}',
                   '{"a":true,}', '{"a":true "b":false}', '{"a":"\\q"}',
                   '{"a":2147483648}', '[' * 2000]
        for body in invalid:
            with self.subTest(body=body[:40]), self.assertRaises(ProtocolError):
                loads(body)
        for body in invalid[:15]:
            if body.isascii():
                with self.subTest(body=body), self.assertRaises(ProtocolError):
                    self.read(frame(body))
        with self.assertRaises(ProtocolError):
            self.read(b'\xff\n')

    def test_oversize_frame_with_and_without_newline(self):
        for data in [b'x' * (MAX_FRAME + 1), b'x' * (MAX_FRAME + 1) + b'\n']:
            with self.assertRaises(ProtocolError):
                Framer(MemorySocket(data)).read()
        self.assertEqual(len(Framer(MemorySocket(b'x' * MAX_FRAME + b'\n')).read()), MAX_FRAME)

    def test_truncated_frame_and_clean_eof(self):
        with self.assertRaises(ProtocolError):
            self.read(frame()[:-1])
        with self.assertRaises(EOFError):
            self.read(b'')

    def test_body_limit(self):
        for body in ['{"a":"' + 'a' * MAX_BODY + '"}']:
            with self.assertRaises(ProtocolError):
                self.read(frame(body))
        proto = Proto(MemorySocket(), SECRET, SID, "server")
        with self.assertRaises(ProtocolError):
            proto.send({"a": "a" * MAX_BODY})

    def test_absolute_deadline_despite_drip_feed(self):
        a, b = socket.socketpair()
        errors = []
        def drip():
            try:
                for _ in range(15):
                    b.sendall(b'x')
                    time.sleep(0.02)
            except OSError:
                pass
        thread = threading.Thread(target=drip)
        thread.start()
        started = time.monotonic()
        try:
            with self.assertRaises(TimeoutError):
                Framer(a, timeout=0.08).read()
            self.assertLess(time.monotonic() - started, 0.4)
        finally:
            a.close()
            thread.join()
            b.close()
        self.assertEqual(errors, [])

    def test_mutual_session_binding(self):
        self.assertNotEqual(session_id("1" * 64, "2" * 64), session_id("1" * 64, "3" * 64))
        self.assertNotEqual(session_id("1" * 64, "2" * 64), session_id("3" * 64, "2" * 64))

    def test_secrets_required(self):
        for secret in ("", "short", "é" * 40, "a" * 128, "a " * 20, "change_me" + "a" * 40):
            with self.subTest(secret_length=len(secret)), self.assertRaises(ValueError):
                validate_secret(secret)
        validate_secret(SECRET)

    def test_command_boundaries(self):
        valid = [{"action": "type", "text": "x" * 256}, {"action": "delay", "text": "0"},
                 {"action": "delay", "text": "5000"}, {"action": "key", "keys": "CTRL ALT DEL"},
                 {"action": "key", "keys": "GUI r"}, {"action": "ping"}]
        for command in valid:
            self.assertEqual(validate_command(command), command)
        invalid = [{"action": "type", "text": "x" * 257}, {"action": "type", "text": ""},
                   {"action": "type", "text": "é"}, {"action": "type", "text": "\x00"},
                   {"action": "type", "text": "\r"}, {"action": "delay", "text": "-1"},
                   {"action": "delay", "text": "5001"}, {"action": "delay", "text": "01"},
                   {"action": "delay", "text": "1x"}, {"action": "delay", "text": 1},
                   {"action": "key", "keys": "CTRL a b"}, {"action": "key", "keys": "UNKNOWN a"},
                   {"action": "key", "keys": "CTRL  a"}, {"action": "key", "keys": "CTRL CTRL a"},
                   {"action": "ping", "text": "x"}, {"action": "auth"}, {"action": []}]
        for command in invalid:
            with self.subTest(command=command), self.assertRaises(ProtocolError):
                validate_command(command)

    def test_rate_limit_and_exact_expiry(self):
        now = [0.0]
        rate = RateLimiter(clock=lambda: now[0])
        self.assertEqual([rate.allow() for _ in range(35)], [True] * 30 + [False] * 5)
        now[0] = 59.999
        self.assertFalse(rate.allow())
        now[0] = 60
        self.assertTrue(rate.allow())

    def test_ducky_exact_events_and_rejection(self):
        self.assertEqual(parse_ducky("REM comment\nSTRING abc  \nENTER\nDELAY 10\nCTRL a"),
                         [{"action": "type", "text": "abc  "}, {"action": "key", "keys": "ENTER"},
                          {"action": "delay", "text": "10"}, {"action": "key", "keys": "CTRL a"}])
        for script in ("DELAY -1", "REMINDER", "STRING", "CTRL a b"):
            with self.assertRaises(ValueError):
                parse_ducky(script)

    def test_backoff_bounds(self):
        for attempt in range(100):
            for sample in (0, 0.5, 1):
                self.assertTrue(1 <= backoff_delay(attempt, sample) <= 60)
        self.assertEqual([backoff_delay(i, .5) for i in range(8)], [1, 2, 4, 8, 16, 32, 60, 60])

    def test_invalid_encoder_data_is_rejected(self):
        for value in ([1], {"x": object()}, {"x": float('nan')}):
            with self.assertRaises(ProtocolError):
                dumps(value)
