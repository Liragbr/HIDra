"""SDK-dependent integration check. POSIX BIO replaces only the CYW43/lwIP transport."""
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test.test_integration import IntegrationFixture


class MbedTLSChecks(IntegrationFixture):
    def check_client(self, ca, hostname, config=None):
        server = self.start([], config)
        binary = str(Path(__file__).resolve().parents[1] / 'build/mbedtls-host/client')
        return subprocess.run([binary, str(ca), str(server.address[1]), hostname],
                              capture_output=True, text=True, timeout=5)

    def test_valid_tls13_auth_and_exit(self):
        result = self.check_client(self.certs / 'ca.pem', 'localhost')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PASS:', result.stdout)

    def test_reject_wrong_ca(self):
        result = self.check_client(self.other / 'ca.pem', 'localhost')
        self.assertEqual(result.returncode, 1)
        self.assertIn('-0x2700', result.stderr)  # X509 verification failed, not an arbitrary failure.

    def test_reject_wrong_hostname(self):
        result = self.check_client(self.certs / 'ca.pem', 'wrong.invalid')
        self.assertEqual(result.returncode, 1)
        self.assertIn('-0x2700', result.stderr)

    def test_reject_expired_certificate(self):
        config = self.config()
        config.CERT = str(self.certs / 'expired.pem')
        result = self.check_client(self.certs / 'ca.pem', 'localhost', config)
        self.assertEqual(result.returncode, 1)
        self.assertIn('-0x2700', result.stderr)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(MbedTLSChecks)
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
