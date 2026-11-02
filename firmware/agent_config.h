/**
 * agent_config.h — compile-time configuration for Pico W C2 agent
 *
 * Edit this file before building.  All values are baked into flash.
 *
 * SECURITY NOTE:
 *   These strings are stored in plain-text in the Pico's flash memory.
 *   Anyone who physically disassembles the UF2 can read them.
 *   Treat the device as untrusted if it leaves your control.
 *
 *   For a more hardened build, use pico-sdk's flash encryption support
 *   (RP2350 only, requires secure boot configuration).
 */

#ifndef AGENT_CONFIG_H
#define AGENT_CONFIG_H

/* ── Wi-Fi credentials ─────────────────────────────────────────────── */
#define WIFI_SSID   "your_lab_network"
#define WIFI_PASS   "your_wifi_password"

/* ── C2 server ─────────────────────────────────────────────────────── */
#define C2_HOST     "192.168.1.100"   /* IP or hostname of your C2 server */
#define C2_PORT     9000

/* ── Authentication (must match server config) ─────────────────────── */
#define RUNNER_TOKEN        "change_me_long_random_token"
#define RUNNER_HMAC_SECRET  "change_me_long_random_hmac_secret"

/* ── TLS CA certificate ─────────────────────────────────────────────
 * Defined in ca_cert.h — see gen_certs.sh to generate a self-signed CA.
 * If building with AGENT_LAB_MODE=1 this is not used.
 */

#endif /* AGENT_CONFIG_H */
