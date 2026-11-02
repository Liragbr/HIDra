cmake_minimum_required(VERSION 3.13)

# ── Pico SDK bootstrap ────────────────────────────────────────────────
# Set PICO_SDK_PATH env var OR pass -DPICO_SDK_PATH=... to cmake
include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(pico_c2_agent C CXX ASM)
set(CMAKE_C_STANDARD   11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

# ── Optional lab mode (TLS cert verification disabled) ────────────────
# cmake -DAGENT_LAB_MODE=1 .. to build without cert checking
option(AGENT_LAB_MODE "Disable TLS certificate verification (lab only)" OFF)

# ── jsmn single-header JSON parser ───────────────────────────────────
# Download: https://raw.githubusercontent.com/zserge/jsmn/master/jsmn.h
# Place jsmn.h in this directory and add a jsmn.c shim:
#   #define JSMN_IMPLEMENTATION
#   #include "jsmn.h"
add_library(jsmn STATIC jsmn.c)
target_include_directories(jsmn PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# ── Main firmware target ──────────────────────────────────────────────
add_executable(pico_c2_agent
    main.c
    usb_descriptors.c
)

# Board selection: pass -DPICO_BOARD=pico_w (RP2040) or pico2_w (RP2350)
# Default to pico_w if not specified
if(NOT DEFINED PICO_BOARD)
    set(PICO_BOARD pico_w)
endif()

target_include_directories(pico_c2_agent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ── Link libraries ────────────────────────────────────────────────────
target_link_libraries(pico_c2_agent
    # Pico SDK fundamentals
    pico_stdlib
    pico_multicore
    pico_time

    # CYW43 Wi-Fi — threadsafe background mode plays well with TinyUSB
    pico_cyw43_arch_lwip_threadsafe_background

    # TinyUSB device stack (HID)
    tinyusb_device
    tinyusb_board

    # mbedTLS (bundled in pico-sdk via pico_lwip)
    pico_mbedtls

    # Watchdog for remote reboot on "terminate"
    hardware_watchdog

    # jsmn JSON parser
    jsmn
)

# ── mbedTLS config ────────────────────────────────────────────────────
# Overrides the pico-sdk default mbedtls_config.h with our lean one
target_compile_definitions(pico_c2_agent PRIVATE
    MBEDTLS_CONFIG_FILE="mbedtls_config.h"
)

# ── Lab mode flag ─────────────────────────────────────────────────────
if(AGENT_LAB_MODE)
    target_compile_definitions(pico_c2_agent PRIVATE AGENT_LAB_MODE=1)
    message(WARNING "AGENT_LAB_MODE is ON — TLS cert verification disabled!")
endif()

# ── USB / stdio routing ───────────────────────────────────────────────
# USB stdio → serial monitor while developing; disable in production
# to free USB for HID-only operation.
pico_enable_stdio_usb(pico_c2_agent 0)   # 0 = off (HID owns USB)
pico_enable_stdio_uart(pico_c2_agent 1)  # use UART0 (GP0/GP1) for debug

# ── Generate UF2 + map + disassembly ─────────────────────────────────
pico_add_extra_outputs(pico_c2_agent)
