#include "shdccp.h"
#include <limits.h>
#if CHAR_BIT != 8
#error "This wire codec requires 8-bit octets"
#endif

int shdccp_pack(shdccp_fields f, shdccp_halves *out) {
    if (!out || f.scale > 15 || f.stream_slot > 15 || f.form_id > 15 ||
        f.step_index > 15 || f.structure > 3 || f.wheel_unit > 7 ||
        f.cycle_step > 7) return -1;
    out->lo = f.core;
    out->hi = ((uint32_t)f.scale)
            | ((uint32_t)f.stream_slot << 4)
            | ((uint32_t)f.form_id << 8)
            | ((uint32_t)f.step_index << 12)
            | ((uint32_t)f.gate << 16)
            | ((uint32_t)f.structure << 24)
            | ((uint32_t)f.wheel_unit << 26)
            | ((uint32_t)f.cycle_step << 29);
    return 0;
}
void shdccp_unpack(shdccp_halves w, shdccp_fields *out) {
    if (!out) return;
    out->core = w.lo;
    out->scale = (uint8_t)(w.hi & 15u);
    out->stream_slot = (uint8_t)((w.hi >> 4) & 15u);
    out->form_id = (uint8_t)((w.hi >> 8) & 15u);
    out->step_index = (uint8_t)((w.hi >> 12) & 15u);
    out->gate = (uint8_t)((w.hi >> 16) & 255u);
    out->structure = (uint8_t)((w.hi >> 24) & 3u);
    out->wheel_unit = (uint8_t)((w.hi >> 26) & 7u);
    out->cycle_step = (uint8_t)((w.hi >> 29) & 7u);
}
void shdccp_to_be_bytes(shdccp_halves w, uint8_t bytes[8]) {
    for (unsigned i=0; i<4; ++i) {
        bytes[i] = (uint8_t)(w.hi >> (24-8*i));
        bytes[i+4] = (uint8_t)(w.lo >> (24-8*i));
    }
}
shdccp_halves shdccp_from_be_bytes(const uint8_t bytes[8]) {
    shdccp_halves w = {0,0};
    for (unsigned i=0; i<4; ++i) {
        w.hi = (w.hi << 8) | bytes[i];
        w.lo = (w.lo << 8) | bytes[i+4];
    }
    return w;
}
/* IEEE 802.3 reflected CRC-32, only an error-detection checksum. */
uint32_t shdccp_crc32_ieee(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xffffffffu;
    for (size_t i=0; i<len; ++i) {
        crc ^= (uint32_t)buf[i];
        for (unsigned b=0; b<8; ++b)
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return crc ^ 0xffffffffu;
}
uint64_t shdccp_xor_parity64(const uint64_t words[3]) {
    return words[0] ^ words[1] ^ words[2];
}
