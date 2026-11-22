#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${PICO_MBEDTLS_PATH:?set PICO_MBEDTLS_PATH to pinned mbedTLS 3.6.8}"
mkdir -p build/mbedtls-host
cc -O2 -std=c11 -D_POSIX_C_SOURCE=200809L '-DMBEDTLS_CONFIG_FILE="hidra_mbedtls_config.h"' \
  -Ifirmware -I"$PICO_MBEDTLS_PATH/include" -I"$PICO_MBEDTLS_PATH/library" \
  "$PICO_MBEDTLS_PATH"/library/*.c firmware/protocol.c test/native/mbedtls_client.c \
  -o build/mbedtls-host/client
python3 test/validate_mbedtls.py
