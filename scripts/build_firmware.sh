#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
case "${1:-}" in pico_w|pico2_w) board="$1" ;; *) echo 'usage: build_firmware.sh pico_w|pico2_w' >&2; exit 2 ;; esac
: "${PICO_SDK_PATH:?set PICO_SDK_PATH}"
: "${PICO_MBEDTLS_PATH:?set PICO_MBEDTLS_PATH}"
python3 scripts/check_dependencies.py
cmake -S firmware -B "firmware/build-$board" -G Ninja \
  -DPICO_BOARD="$board" -DPICO_SDK_PATH="$PICO_SDK_PATH" \
  -DPICO_MBEDTLS_PATH="$PICO_MBEDTLS_PATH" -DPICO_NO_PICOTOOL=0
cmake --build "firmware/build-$board" --parallel 4
test -s "firmware/build-$board/pico_c2_agent.uf2"
arm-none-eabi-size "firmware/build-$board/pico_c2_agent.elf"
