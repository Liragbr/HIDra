"""Check source identities, not merely version labels. Does not claim a complete CVE scan."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
lock = json.loads((ROOT / 'dependencies.lock.json').read_text())


def check(path, expected):
    actual = subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != expected:
        raise SystemExit(f'dependency revision mismatch: {path.name}')
    if subprocess.check_output(['git', '-C', str(path), 'status', '--porcelain', '--untracked-files=normal'], text=True).strip():
        raise SystemExit(f'dependency has local changes: {path.name}')


sdk = Path(os.environ['PICO_SDK_PATH'])
mbed = Path(os.environ['PICO_MBEDTLS_PATH'])
check(sdk, lock['pico_sdk']['commit'])
check(mbed, lock['mbedtls']['commit'])
for relative, commit in lock['sdk_submodules'].items():
    check(sdk / relative, commit)
print('PASS: SDK, mbedTLS override and required submodules match immutable lock')
