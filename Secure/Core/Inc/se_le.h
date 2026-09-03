/**
 * @file    se_le.h
 * @brief   Little-endian u16/u32 load/store for wire formats (LV, OTP, NV)
 */
#ifndef SE_LE_H
#define SE_LE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline uint16_t se_u16le(const uint8_t *p)
{
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static inline uint32_t se_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void se_put_u16le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static inline void se_put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static inline void se_append_u16le(uint8_t *buf, uint32_t *off, uint16_t v)
{
    se_put_u16le(buf + *off, v);
    *off += 2U;
}

static inline void se_append_u32le(uint8_t *buf, uint32_t *off, uint32_t v)
{
    se_put_u32le(buf + *off, v);
    *off += 4U;
}

#ifdef __cplusplus
}
#endif

#endif /* SE_LE_H */
