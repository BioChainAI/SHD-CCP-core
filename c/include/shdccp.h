#ifndef SHDCCP_H
#define SHDCCP_H
#include <stdint.h>
#include <stddef.h>

/* Reference encoder for the fixed Einstein Tile v1 header and raw 32-bit core.
 * Important: This does NOT validate Form 1 Hurwitz canonicality, authenticate
 * packets, or implement the external 15-form codex definitions. */
#ifdef __cplusplus
extern "C" {
#endif

typedef struct { uint32_t hi, lo; } shdccp_halves;
typedef struct {
    uint32_t core;
    uint8_t scale, stream_slot, form_id, step_index, gate;
    uint8_t structure, wheel_unit, cycle_step;
} shdccp_fields;

/* Reject out-of-range values instead of silently masking. */
int shdccp_pack(shdccp_fields f, shdccp_halves *out);
void shdccp_unpack(shdccp_halves w, shdccp_fields *out);
void shdccp_to_be_bytes(shdccp_halves w, uint8_t bytes[8]);
shdccp_halves shdccp_from_be_bytes(const uint8_t bytes[8]);
uint32_t shdccp_crc32_ieee(const uint8_t *buf, size_t len);
uint64_t shdccp_xor_parity64(const uint64_t words[3]);
#ifdef __cplusplus
}
#endif
#endif
