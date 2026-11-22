"""Compile the actual firmware codec; exchange independently signed Python/C frames."""
import ctypes as c
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from hidra.protocol import Proto, ProtocolError, dumps, validate_command
from test.test_protocol import SECRET, SID, MemorySocket, frame

ROOT = Path(__file__).resolve().parents[1]


class NativeProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='hidra-native-')
        library = Path(cls.temp.name) / 'codec.so'
        subprocess.run(['gcc', '-shared', '-fPIC', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-Wconversion', '-Wshadow', '-I', str(ROOT / 'firmware'),
                        str(ROOT / 'firmware/protocol.c'), str(ROOT / 'test/native/crypto_adapter.c'),
                        '-lcrypto', '-o', str(library)], check=True, capture_output=True)
        cls.lib = c.CDLL(str(library))
        for name in ('test_encode', 'test_decode'):
            fn = getattr(cls.lib, name)
            fn.restype = c.c_bool
            fn.argtypes = [c.c_char_p, c.c_char_p, c.c_uint32, c.c_char_p, c.c_char_p, c.c_void_p, c.c_size_t]
        cls.lib.hidra_command.restype = c.c_bool
        cls.lib.hidra_command.argtypes = [c.c_char_p, c.c_void_p, c.c_void_p]
        cls.lib.hidra_rate_allow.restype = c.c_bool
        cls.lib.hidra_rate_allow.argtypes = [c.c_uint32, c.POINTER(c.c_uint32), c.POINTER(c.c_uint)]

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def encode(self, body, seq=1):
        out = c.create_string_buffer(2049)
        self.assertTrue(self.lib.test_encode(SECRET.encode(), SID.encode(), seq, b's2a', body.encode(), out, len(out)))
        return out.value

    def decode(self, data, seq=1, direction=b's2a', sid=SID):
        out = c.create_string_buffer(769)
        ok = self.lib.test_decode(SECRET.encode(), sid.encode(), seq, direction, data, out, len(out))
        return ok, out.value

    def test_c_encoder_to_python(self):
        for msg in [{"action": "ping"}, {"ok": True}, {"action": "type", "text": '"\\\n\t' + 'x' * 200}]:
            wire = self.encode(dumps(msg))
            self.assertEqual(Proto(MemorySocket(wire + b'\n'), SECRET, SID, 'agent').recv(), msg)

    def test_python_encoder_to_c(self):
        for value in ['ASCII', '"\\\n\t', '\\u0041', 'x' * 256]:
            body = dumps({"action": "type", "text": value})
            ok, decoded = self.decode(frame(body).rstrip(b'\n'))
            self.assertTrue(ok)
            self.assertEqual(decoded.decode(), body)

    def test_escape_decoding_and_duplicate_fields(self):
        data = frame().rstrip(b'\n').replace(b'"body"', b'"bo\\u0064y"')
        self.assertTrue(self.decode(data)[0])
        duplicate = data[:-1] + b',"body":"x"}'
        self.assertFalse(self.decode(duplicate)[0])

    def test_invalid_hmac_sequence_session_direction_and_types(self):
        invalid = [frame(sig='0' * 64), frame(seq=2), frame(sid='2' * 64),
                   frame(direction='a2s'), frame(v=True), frame(sig=1), frame(sig=''),
                   frame(body='{"action":null}'), frame(body='[]'), frame(body='{}{}'),
                   frame(body='{"x":1,"x":2}'), frame(body='{"x":"\\u0000"}'),
                   frame(body='{"x":"\\ud800"}'), frame(body='{"x":"\\q"}'),
                   frame(body='{"x":01}'), frame(body='{"x":true,}'), frame(body='{"x":{}}')]
        for data in invalid:
            with self.subTest(data=data[:40]):
                self.assertFalse(self.decode(data.rstrip(b'\n'))[0])
        self.assertFalse(self.decode(frame().rstrip(b'\n'), seq=0)[0])

    def test_all_truncations_rejected(self):
        wire = self.encode('{"action":"ping"}')
        for end in range(len(wire)):
            with self.subTest(end=end):
                self.assertFalse(self.decode(wire[:end])[0])

    def test_small_output_and_oversized_inputs_rejected(self):
        out = c.create_string_buffer(10)
        self.assertFalse(self.lib.test_encode(SECRET.encode(), SID.encode(), 1, b's2a',
                                              b'{"ok":true}', out, len(out)))
        self.assertFalse(self.decode(b'x' * 2049)[0])
        self.assertFalse(self.decode(frame('{"x":"' + 'a' * 769 + '"}').rstrip(b'\n'))[0])

    def test_command_validation_parity(self):
        commands = [{"action": "type", "text": t} for t in ('x', '', 'x' * 256, 'x' * 257, '\r', '\t')]
        commands += [{"action": "delay", "text": t} for t in ('0','01','5000','5001','-1','1x')]
        commands += [{"action": "key", "keys": t} for t in ('GUI r','CTRL ALT DEL','CTRL','CTRL a b','CTRL  a','?', 'CTRL CTRL a')]
        commands += [{"action": "ping"}, {"action": "ping", "text": "x"}, {"action": "type", "text": 42}]
        for command in commands:
            try:
                validate_command(command)
                expected = True
            except ProtocolError:
                expected = False
            action, payload = c.create_string_buffer(16), c.create_string_buffer(257)
            with self.subTest(command=command):
                self.assertEqual(self.lib.hidra_command(json.dumps(command).encode(), action, payload), expected)
                if expected:
                    self.assertEqual(action.value.decode(), command['action'])
                    self.assertEqual(payload.value.decode(), command.get('text', command.get('keys','')))

    def test_firmware_rate_limit_at_boot_expiry_and_wrap(self):
        for start in (0, 100, 2**32 - 100):
            timestamps, count = (c.c_uint32 * 30)(), c.c_uint(0)
            outcomes = [self.lib.hidra_rate_allow(start, timestamps, c.byref(count)) for _ in range(35)]
            self.assertEqual(outcomes, [True] * 30 + [False] * 5)
            self.assertFalse(self.lib.hidra_rate_allow((start + 59999) % 2**32, timestamps, c.byref(count)))
            self.assertTrue(self.lib.hidra_rate_allow((start + 60000) % 2**32, timestamps, c.byref(count)))
