/* Copy to agent_config.local.h. Never commit real credentials or generated UF2s. */
#define WIFI_SSID "your_lab_network"
#define WIFI_PASS "your_wifi_password"
#define C2_ADDRESS "192.168.1.100" /* Numeric IPv4 transport address. */
#define C2_HOST "hidra.lab"        /* Certificate DNS SAN / expected server identity. */
#define C2_PORT 9000
#define RUNNER_TOKEN "change_me_generate_32_random_bytes_as_hex"
#define RUNNER_HMAC_SECRET "change_me_generate_an_independent_secret"
