#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${PICO_SDK_PATH:?set PICO_SDK_PATH to pinned SDK}"
mkdir -p build/mbedtls-host
cc -O2 -std=c11 -D_POSIX_C_SOURCE=200809L '-DMBEDTLS_CONFIG_FILE="hidra_mbedtls_config.h"' \
  -Ifirmware -I"$PICO_SDK_PATH/lib/mbedtls/include" -I"$PICO_SDK_PATH/lib/mbedtls/library" \
  "$PICO_SDK_PATH"/lib/mbedtls/library/*.c firmware/protocol.c test/native/mbedtls_client.c \
  -o build/mbedtls-host/client
python3 test/validate_mbedtls.py
