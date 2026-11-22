"""Small auditable guard against publishing local provisioning material."""
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[1]
paths = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
private_key = re.compile(rb'^-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----', re.MULTILINE)
failures = []
for name in filter(None, paths):
    path = root / name
    if not path.exists():
        continue
    if path.name in {'agent_config.local.h', 'ca_cert.h'} or path.suffix in {'.pem', '.key', '.uf2', '.elf'}:
        failures.append(name)
    elif private_key.search(path.read_bytes()):
        failures.append(name)
if failures:
    raise SystemExit('Forbidden provisioning material: ' + ', '.join(failures))
print('PASS: no tracked private keys, local credentials, certificates or firmware binaries')
