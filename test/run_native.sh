#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/native
cc -std=c11 -g -O1 -Wall -Wextra -Werror -Wconversion -Wshadow \
  -fsanitize=address,undefined -fno-omit-frame-pointer -pthread -Ifirmware \
  firmware/protocol.c firmware/hid_queue.c test/native/sanitizer.c -o build/native/sanitizer
ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:halt_on_error=1}" UBSAN_OPTIONS=halt_on_error=1 build/native/sanitizer
