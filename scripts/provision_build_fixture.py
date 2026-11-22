"""CI compile fixture only. Public invalid lab credentials; never deploy this image."""
from pathlib import Path
import shutil
import subprocess

root = Path(__file__).resolve().parents[1]
config = root / 'firmware/agent_config.local.h'
ca_header = root / 'firmware/ca_cert.h'
if config.exists() or ca_header.exists():
    raise SystemExit('refusing to overwrite existing provisioning')
certs = root / 'build' / 'ci-certs'
certs.parent.mkdir(exist_ok=True)
subprocess.run(['bash', str(root / 'gen_certs.sh'), str(certs)], check=True)
shutil.copyfile(certs / 'ca_cert.h', ca_header)
example = (root / 'firmware/agent_config.example.h').read_text()
example = example.replace('change_me_generate_32_random_bytes_as_hex', 'build-only-token-00000000000000000000000000000001')
example = example.replace('change_me_generate_an_independent_secret', 'build-only-hmac-000000000000000000000000000000002')
config.write_text(example)
