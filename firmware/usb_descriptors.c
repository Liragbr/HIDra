/**
 * usb_descriptors.c — TinyUSB USB/HID descriptor tables
 *
 * Presents the Pico W to the host as a standard HID keyboard.
 * VID/PID are set to Raspberry Pi Foundation values; change them
 * if you want the device to appear as something else.
 *
 * The device uses a SINGLE configuration with ONE HID interface
 * exposing ONE IN endpoint (keyboard reports, 8 bytes).
 */

#include "tusb.h"
#include "usb_descriptors.h"

/* ── Device descriptor ──────────────────────────────────────────────── */
tusb_desc_device_t const desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,
    .bDeviceClass       = 0x00,
    .bDeviceSubClass    = 0x00,
    .bDeviceProtocol    = 0x00,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
    /* Raspberry Pi Foundation VID/PID — change to spoof a different device */
    .idVendor           = 0x2E8A,
    .idProduct          = 0x0004,
    .bcdDevice          = 0x0100,
    .iManufacturer      = 0x01,
    .iProduct           = 0x02,
    .iSerialNumber      = 0x03,
    .bNumConfigurations = 0x01,
};

uint8_t const * tud_descriptor_device_cb(void) {
    return (uint8_t const *)&desc_device;
}

/* ── HID report descriptor — standard boot-protocol keyboard ────────── */
uint8_t const desc_hid_report[] = {
    TUD_HID_REPORT_DESC_KEYBOARD(HID_REPORT_ID(REPORT_ID_KEYBOARD))
};

uint8_t const * tud_hid_descriptor_report_cb(uint8_t instance) {
    (void)instance;
    return desc_hid_report;
}

/* ── Configuration + interface descriptors ──────────────────────────── */
#define CONFIG_TOTAL_LEN  (TUD_CONFIG_DESC_LEN + TUD_HID_DESC_LEN)
#define EPNUM_HID         0x81   /* IN endpoint 1 */

uint8_t const desc_configuration[] = {
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, CONFIG_TOTAL_LEN,
                          TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),
    TUD_HID_DESCRIPTOR(0, 0, HID_ITF_PROTOCOL_KEYBOARD,
                       sizeof(desc_hid_report), EPNUM_HID,
                       CFG_TUD_HID_EP_BUFSIZE, 10),
};

uint8_t const * tud_descriptor_configuration_cb(uint8_t index) {
    (void)index;
    return desc_configuration;
}

/* ── String descriptors ─────────────────────────────────────────────── */
char const * string_desc_arr[] = {
    (const char[]){0x09, 0x04},   /* 0: English (0x0409)              */
    "RaspberryPi",                /* 1: Manufacturer                  */
    "Pico W Keyboard",            /* 2: Product                       */
    "000001",                     /* 3: Serial number                 */
};

static uint16_t _desc_str[32];

uint16_t const * tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void)langid;
    uint8_t chr_count;

    if (index == 0) {
        memcpy(&_desc_str[1], string_desc_arr[0], 2);
        chr_count = 1;
    } else {
        if (index >= sizeof(string_desc_arr) / sizeof(string_desc_arr[0]))
            return NULL;
        const char *str = string_desc_arr[index];
        chr_count = (uint8_t)strlen(str);
        if (chr_count > 31) chr_count = 31;
        for (uint8_t i = 0; i < chr_count; i++)
            _desc_str[1 + i] = str[i];
    }
    _desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * chr_count + 2));
    return _desc_str;
}
