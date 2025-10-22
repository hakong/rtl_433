/** @file
    Typhur Sync Gold probe transmitter (Lite/Dual/Quad variants).

    Contributed by @hakong
    With guidance from Christian W. Zuckschwerdt (@zuckschwerdt)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

/**
Typhur Sync Gold probe protocol notes.

- Reverse-engineered from on-air captures by @hakong With guidance from Christian W. Zuckschwerdt (@zuckschwerdt)
- Probe transmits on 915 MHz; interval observed ≈2 s while active.
- Modulation: FSK_PULSE_PCM, ~12.5 µs/bit.
- Framing: long 0xAA preamble; sync 0x57 0x54; payload 24 bytes.
- Integrity: CRC-16 (poly 0x8005, init 0x0000) over bytes 0..21; CRC is stored big-endian at bytes 22..23.

Data layout (byte offsets; little-endian unless noted):
    00..02  ID (24 bits, bytes big-endian; printed as %06x)
    03      ? (observed constant)
    04      status (bit 3 = 1 when in base/charging)
    05      ? (observed constant)
    06..07  Probe T1  (centi-°C, u16 LE)
    08..09  Probe T2  (centi-°C, u16 LE)
    10..11  Probe T3  (centi-°C, u16 LE)
    12..13  Probe T4  (centi-°C, u16 LE)
    14..15  Probe T5  (centi-°C, u16 LE)
    16..17  Ambient   (deci-°C,  u16 LE)
    18..19  Battery   (centi-V,  u16 LE)
    20..21  Counter   (u16 LE)
    22..23  CRC-16    (MSB, LSB)

Notes:
- The **base/receiver** listens at 915 MHz and bridges via 2.4 GHz (BLE/Wi-Fi); this decoder targets the probe RF only.
- Likely rebrands exist (e.g., ThermoMaven G1/G2/G4): enclosures/manuals/FCC filings appear mostly identical and report the same band, but this has not been RF-verified here.
*/

#include "decoder.h"
#include "bitbuffer.h"
#include <stdint.h>

static int typhur_sync_gold_decode(r_device *decoder, bitbuffer_t *bb)
{
    /* Preamble is long 0xAA; sync word is 0x57 0x54; payload is 24 bytes. */
    static const uint8_t SYNC[2] = {0x57, 0x54};

    enum {
        PAYLOAD_LEN  = 24,
        PAYLOAD_BITS = PAYLOAD_LEN * 8,
        SYNC_BITS    = 16,
    };

    for (unsigned row = 0; row < bb->num_rows; row++) {
        unsigned row_bits = bb->bits_per_row[row];
        if (row_bits < SYNC_BITS + PAYLOAD_BITS)
            continue;

        int bitpos = 0;
        const int last_start = (int)row_bits - (SYNC_BITS + PAYLOAD_BITS);
        int tries = 0, tries_max = (int)row_bits;

        while (bitpos <= last_start && tries++ < tries_max) {
            int sync_at = bitbuffer_search(bb, row, bitpos, SYNC, SYNC_BITS);

            if (sync_at < 0) break;

            const int start = sync_at + SYNC_BITS;
            if (start + PAYLOAD_BITS > (int)row_bits) break; // nothing more usable in this row

            uint8_t pkt[PAYLOAD_LEN];
            bitbuffer_extract_bytes(bb, row, start, pkt, PAYLOAD_BITS);

            const uint16_t rx_crc   = (uint16_t)((pkt[22] << 8) | pkt[23]);
            const uint16_t calc_crc = crc16(pkt, 22, 0x8005, 0x0000);

            if (rx_crc == calc_crc) {
                // Parse fields (little-endian ID and values as observed)
                uint32_t id = (uint32_t)((pkt[0] << 16) | (pkt[1] << 8) | pkt[2]);
                uint8_t  charge = pkt[4];                     // charging/base status byte
                int      in_base = (charge & 0x08) ? 1 : 0;   // F4=not in base, FC=in base (bit 3)

                // Temps are centi-degrees for probes, tenth-degree for ambient
                double t1 = (pkt[6]  | (pkt[7]  << 8)) / 100.0;
                double t2 = (pkt[8]  | (pkt[9]  << 8)) / 100.0;
                double t3 = (pkt[10] | (pkt[11] << 8)) / 100.0;
                double t4 = (pkt[12] | (pkt[13] << 8)) / 100.0;
                double t5 = (pkt[14] | (pkt[15] << 8)) / 100.0;
                double amb = (pkt[16] | (pkt[17] << 8)) / 10.0;
                double batt_v = (pkt[18] | (pkt[19] << 8)) / 100.0;
                unsigned counter = (unsigned)(pkt[20] | (pkt[21] << 8));

                /* clang-format off */
                data_t *data = data_make(
                    "model",        "Model",        DATA_STRING, "Typhur-SyncGold",
                    "id",           "ID",           DATA_FORMAT, "%06x", DATA_INT, id,
                    "in_base",      "InBase",       DATA_INT,    in_base,
                    "counter",      "Counter",      DATA_INT,    counter,
                    "battery_V",    "Battery",      DATA_DOUBLE, batt_v,
                    "temp_1_C",     "T1",           DATA_DOUBLE, t1,
                    "temp_2_C",     "T2",           DATA_DOUBLE, t2,
                    "temp_3_C",     "T3",           DATA_DOUBLE, t3,
                    "temp_4_C",     "T4",           DATA_DOUBLE, t4,
                    "temp_5_C",     "T5",           DATA_DOUBLE, t5,
                    "ambient_C",    "Ambient",      DATA_DOUBLE, amb,
                    "mic",          "Integrity",    DATA_STRING, "CRC",
                    NULL);
                /* clang-format on */

                decoder_output_data(decoder, data);
                return 1;
            }
            bitpos = sync_at + SYNC_BITS;
        }
    }
    return 0;
}

static const char *const typhur_sync_gold_fields[] = {
    "model",
    "id",
    "in_base",
    "counter",
    "battery_V",
    "temp_1_C",
    "temp_2_C",
    "temp_3_C",
    "temp_4_C",
    "temp_5_C",
    "ambient_C",
    "mic",
    NULL,
};

r_device const typhur_sync_gold = {
    .name        = "Typhur Sync Gold",
    .modulation  = FSK_PULSE_PCM,
    .short_width = 13,   // ~12.5 µs/bit observed
    .long_width  = 13,
    .tolerance   = 10,
    .reset_limit = 3000,
    .decode_fn   = &typhur_sync_gold_decode,
    .fields      = typhur_sync_gold_fields,
};
