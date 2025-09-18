/** @file
    Decoder for Typhur Sync Gold, tested with Typhur Sync Gold Lite.

    Copyright (C) 2025

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
 */
#include "decoder.h"
#include "bitbuffer.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h> // getenv
#include <string.h>
#include <stdio.h>
#include <time.h> // uptime-derived timestamp

/**
Decoder for Typhur Sync Gold, tested with Typhur Sync Gold Lite.

FCC ID: 2BEFM-WTP3000 (https://fcc.report/FCC-ID/2BEFM-WTP3000)

- Center frequency: ~915 MHz
- Modulation: GFSK (handled by rtl_433 as FSK_PCM)
- Symbol rate: ~80 kbps (12.5 µs / bit)
- Capture: 2 Msps SDR, ~25 samples/bit works cleanly
- Framing: long 0xAA preamble (alternating bits), then sync word 0x57 0x54 (bitbench align: aaaaaaaaa5754)
- Payload length (post-sync): 24 bytes (192 bits)
- Charging/base status: f4 (not charging, not in base) fc (charging, in base).
- The probe broadcasts every 2 seconds
- When probe is put in base, it sends 4 fast (~0.72 seconds between) repeating transmissions
- When probe is taken out of base, it sends 3 repeated bursts (about 1 second between)

Data example:
9d3701a0f4577e0987098b098c098d0902011a0101002a2b

Data layout:
ID:24h ?8h CHARGING_STATUS:8h ?8h T_ONE:<16d T_TWO:<16d T_THREE:<16d T_FOUR:<16d T_FIVE:<16d T_AMB:<16d BATT_V:<16d COUNTER:<16d CRC:16h EOM8x

- ID              : 24-bit little-endian unique probe id (e.g., 9D 37 01 → 0x01379D)
- UNKNOWN         : Observed: A0
- CHARGING_STATUS : F4 (not in base, discharging) / FC (charging, in base)
- UNKNOWN         : Observed: 57
- T1..T5          : 16-bit little-endian temps, °C = raw / 100.0 (two decimals)
- AMB             : 16-bit little-endian ambient temp, °C = raw / 10.0 (one decimal)
- BATT            : 16-bit little-endian centivolts, V = raw / 100.0 (LTO 2.4 V nominal. Full: ~2.8V, empty ~1.9V)
- COUNTER         : 16-bit little-endian counter (monotonic)
- CRC             : 16-bit CRC over all preceding payload bytes (see below)

# Guesses on the two unknown's: model and firmware version maybe?

CRC / MIC
---------
- CRC-16/UMTS parameters verified with `reveng`:
    width=16  poly=0x8005  init=0x0000  refin=false  refout=false  xorout=0x0000
- This is the same call shape as other decoders using:
    crc16(buf, len, 0x8005, 0x0000)
- Compare the computed value to the final 16-bit LE CRC field.

Example+layout:
ID:9d3701 ?a0 CHARGING_STATUS:f4 ?57 T_ONE:02430 T_TWO:02439 T_THREE:02443 T_FOUR:02444 T_FIVE:02445 T_AMB:00258 BATT_V:00282 COUNTER:00001 CRC:2a2b

T_ONE: 24.30°C
T_AMB: 25.8°C
BATT_V: 2.82V

*/

// ------- runtime-debug toggle -------
// Flip this to 0 to disable all [typhur] prints by default.
static int debug_on = 0;

// Optional: allow env var override once (TYDBG=0 disables, anything else enables)
static inline int typhur_debug_enabled(void)
{
    static int inited = 0;
    if (!inited) {
        const char *e = getenv("TYDBG");
        if (e)
            debug_on = (*e != '0'); // "0" -> off, others -> on
        inited = 1;
    }
    return debug_on;
}

// ----- compact debug helpers (gated by debug_on)
static inline void tdbg(const char *msg)
{
    if (!typhur_debug_enabled())
        return;
    fprintf(stderr, "[typhur] %s\n", msg);
    fflush(stderr);
}
static inline void tdbg_i2(const char *msg, int a, int b)
{
    if (!typhur_debug_enabled())
        return;
    fprintf(stderr, "[typhur] %s%d,%d\n", msg, a, b);
    fflush(stderr);
}
static inline void tdbg_hex2(const char *msg, unsigned a, unsigned b)
{
    if (!typhur_debug_enabled())
        return;
    fprintf(stderr, "[typhur] %s%02X,%02X\n", msg, a & 0xFF, b & 0xFF);
    fflush(stderr);
}
static inline void tdbg_temps(uint32_t id, double t1, double t2, double t3, double t4, double t5,
        double amb, double batt_v, unsigned counter, bool in_base)
{
    if (!typhur_debug_enabled())
        return;
    fprintf(stderr,
            "[typhur] id=%u T1=%.2fC T2=%.2fC T3=%.2fC T4=%.2fC T5=%.2fC Amb=%.1fC Batt=%.3fV Cnt=%u Base=%u\n",
            id, t1, t2, t3, t4, t5, amb, batt_v, counter, in_base ? 1u : 0u);
    fflush(stderr);
}

// -------- CRC16/BUYPASS (poly 0x8005, init 0x0000, refin=false, refout=false, xorout=0x0000)
static uint16_t crc16_buypass(const uint8_t *p, int len)
{
    uint16_t crc = 0x0000;
    for (int i = 0; i < len; i++) {
        crc ^= (uint16_t)p[i] << 8;
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x8005) : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

static inline uint16_t le16(const uint8_t *pkt, int off)
{
    return (uint16_t)(pkt[off] | (pkt[off + 1] << 8));
}

// Output field order for rtl_433 CSV/text (JSON ignores this, but CSV uses it)
static const char *const typhur_sync_gold_output_fields[] = {
        "model",
        "id",
        "in_base",
        "unknown1_hex", // hex of byte at offset 3
        "unknown2_hex", // hex of byte at offset 5
        "counter",
        "uptime_s",
        "on_since_approx",
        "battery_V",
        "temp_1_C",
        "temp_2_C",
        "temp_3_C",
        "temp_4_C",
        "temp_5_C",
        "ambient_C",
        "mic",
        NULL};

static int typhur_sync_gold_decode(r_device *decoder, bitbuffer_t *bb)
{
    tdbg("entered typhur_sync_gold_decode");

    // Search for sync 0x57 0x54; payload starts immediately after sync.
    static const uint8_t SYNC[2] = {0x57, 0x54};
    const int PAYLOAD_LEN_BITS   = 24 * 8;                         // 192
    const int MIN_ROW_BITS       = 16 /*sync*/ + PAYLOAD_LEN_BITS; // 208

    for (unsigned row = 0; row < bb->num_rows; row++) {
        int row_bits = (int)bb->bits_per_row[row];
        tdbg_i2("row begin, bits,row: ", row_bits, (int)row);

        if (row_bits < MIN_ROW_BITS) {
            tdbg("row too short; skip");
            continue;
        }

        int search_pos = 0;
        while (1) {
            int pos = bitbuffer_search(bb, row, search_pos, SYNC, 16);
            if (pos < 0) {
                tdbg("no more sync in this row");
                break;
            }

            int start_after_sync = pos + 16; // bit index right after sync
            int bits_avail       = row_bits - start_after_sync;
            tdbg_i2("sync hit bitpos, start_after_sync: ", pos, start_after_sync);

            if (bits_avail < PAYLOAD_LEN_BITS) {
                tdbg("not enough bits after start; advance search");
                search_pos = pos + 1;
                continue;
            }

            uint8_t pkt[24];
            bitbuffer_extract_bytes(bb, row, start_after_sync, pkt, PAYLOAD_LEN_BITS);
            tdbg_hex2("payload first2: ", pkt[0], pkt[1]);

            // CRC16/BUYPASS over first 22 bytes; CRC big-endian in pkt[22..23]
            uint16_t rx_crc   = (uint16_t)((pkt[22] << 8) | pkt[23]);
            uint16_t calc_crc = crc16_buypass(pkt, 22);
            if (rx_crc != calc_crc) {
                tdbg_i2("CRC mismatch rx,calc: ", rx_crc, calc_crc);
                search_pos = pos + 1;
                continue;
            }
            tdbg("CRC ok");

            // Parse fields
            uint32_t id         = (uint32_t)((pkt[0] << 16) | (pkt[1] << 8) | pkt[2]);
            uint8_t unknown1    = pkt[3]; // formerly "flags"
            uint8_t charge_base = pkt[4]; // used only to compute in_base
            uint8_t unknown2    = pkt[5]; // formerly "marker"
            bool in_base        = (charge_base & 0x08) != 0;

            double t1        = le16(pkt, 6) / 100.0;
            double t2        = le16(pkt, 8) / 100.0;
            double t3        = le16(pkt, 10) / 100.0;
            double t4        = le16(pkt, 12) / 100.0;
            double t5        = le16(pkt, 14) / 100.0;
            double t_amb     = le16(pkt, 16) / 10.0;
            double batt_v    = le16(pkt, 18) / 100.0;
            uint16_t counter = le16(pkt, 20);
            double core_min = t1, core_max = t1;
            double core[5] = {t1, t2, t3, t4, t5};
            for (int i = 1; i < 5; i++) {
                if (core[i] < core_min)
                    core_min = core[i];
                if (core[i] > core_max)
                    core_max = core[i];
            }

            // Derived values
            uint32_t uptime_s = (uint32_t)counter * 2u;
            char on_since[32] = {0};
            time_t now        = time(NULL);
            time_t on_t       = now - (time_t)uptime_s;
            struct tm *gt     = gmtime(&on_t);
            if (gt)
                strftime(on_since, sizeof(on_since), "%Y-%m-%dT%H:%M:%SZ", gt);

            // Hex helpers for unknowns
            char unknown1_hex[5];
            snprintf(unknown1_hex, sizeof(unknown1_hex), "0x%02X", unknown1);
            char unknown2_hex[5];
            snprintf(unknown2_hex, sizeof(unknown2_hex), "0x%02X", unknown2);

            // labeled debug
            tdbg_temps(id, t1, t2, t3, t4, t5, t_amb, batt_v, counter, in_base);

            // Build CSV "msg" & "codes" fillers
            char msg_buf[64];
            snprintf(msg_buf, sizeof(msg_buf),
                    "base=%u cnt=%u up=%us core_min=%.2fC core_max=%.2fC",
                    in_base ? 1u : 0u, (unsigned)counter, (unsigned)uptime_s,
                    core_min, core_max);

            char codes_hex[24 * 2 + 1];
            for (int i = 0; i < 24; i++)
                sprintf(codes_hex + 2 * i, "%02X", pkt[i]);
            codes_hex[24 * 2] = '\0';

            tdbg("emit data");

            data_t *data = data_make(
                    "model", "", DATA_STRING, "Typhur-SyncGold",
                    "id", "", DATA_INT, id,
                    "in_base", "", DATA_INT, in_base ? 1 : 0,

                    "unknown1_hex", "", DATA_STRING, unknown1_hex,
                    "unknown2_hex", "", DATA_STRING, unknown2_hex,

                    "counter", "", DATA_INT, counter,
                    "uptime_s", "s", DATA_INT, uptime_s,
                    "on_since_approx", "", DATA_STRING, on_since,

                    "battery_V", "V", DATA_DOUBLE, batt_v,
                    "temp_1_C", "C", DATA_DOUBLE, t1,
                    "temp_2_C", "C", DATA_DOUBLE, t2,
                    "temp_3_C", "C", DATA_DOUBLE, t3,
                    "temp_4_C", "C", DATA_DOUBLE, t4,
                    "temp_5_C", "C", DATA_DOUBLE, t5,
                    "ambient_C", "C", DATA_DOUBLE, t_amb,

                    // Fill leading CSV columns:
                    "message", "", DATA_STRING, msg_buf, // -> CSV "msg"
                    "codes", "", DATA_STRING, codes_hex, // -> CSV "codes"

                    "mic", "", DATA_STRING, "CRC",
                    NULL);

            decoder_output_data(decoder, data);
            tdbg("decoded (return 1)");
            return 1; // decoded one packet
        }

        tdbg("row end (no decode)");
    }

    tdbg("no match in any row (return 0)");
    return 0;
}

// Device definition
r_device typhur_sync_gold = {
        .name        = "Typhur Sync Gold",
        .modulation  = FSK_PULSE_PCM, // matches -X m=FSK_PCM
        .short_width = 13,            // ~12.5 us/bit
        .long_width  = 13,
        .tolerance   = 6,
        .reset_limit = 8000, // big window so the whole burst stays in one row
        .decode_fn   = typhur_sync_gold_decode,
        .fields      = typhur_sync_gold_output_fields,
};
