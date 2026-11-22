#!/usr/bin/env bash
# Create a new laboratory CA and server certificate. Never overwrite a trust root.
set -euo pipefail
umask 077
OUTPUT="${1:-lab-certs}"
export SRV_IP="${SRV_IP:-127.0.0.1}" SRV_DNS="${SRV_DNS:-localhost}"
python3 - <<'PY'
import ipaddress, os, re
ipaddress.IPv4Address(os.environ['SRV_IP'])
if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', os.environ['SRV_DNS']):
    raise SystemExit('invalid SRV_DNS')
PY
# mkdir without -p intentionally fails if the destination already exists.
mkdir -- "$OUTPUT"
cd -- "$OUTPUT"
trap 'rm -f server.csr san.ext ca.srl' EXIT
openssl genrsa -out ca.key 2048 2>/dev/null
openssl req -new -x509 -sha256 -key ca.key -out ca.pem -days 3650 \
    -subj '/O=HIDra Lab/CN=HIDra Lab CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl genrsa -out server.key 2048 2>/dev/null
openssl req -new -sha256 -key server.key -out server.csr -subj '/O=HIDra Lab/CN=HIDra Server'
cat > san.ext <<EOF
subjectAltName=IP:${SRV_IP},DNS:${SRV_DNS}
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
basicConstraints=critical,CA:FALSE
EOF
openssl x509 -req -sha256 -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out server.pem -days 90 -extfile san.ext
python3 - <<'PY'
from pathlib import Path
import json
pem = Path('ca.pem').read_text(encoding='ascii')
Path('ca_cert.h').write_text('#ifndef HIDRA_CA_CERT_H\n#define HIDRA_CA_CERT_H\n'
                           'static const char ca_cert_pem[] =\n' +
                           '\n'.join(json.dumps(line + '\n') for line in pem.splitlines()) +
                           ';\n#endif\n', encoding='ascii')
PY
printf 'Created lab certificates. Keep both private keys private; provision only ca.pem/ca_cert.h to clients.\n'
