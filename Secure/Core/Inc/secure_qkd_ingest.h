/**
 * @file    secure_qkd_ingest.h
 */
#ifndef SECURE_QKD_INGEST_H
#define SECURE_QKD_INGEST_H

#include <stdint.h>

#define SECURE_QKD_INGEST_CHUNK   0u
#define SECURE_QKD_INGEST_FINISH  1u
#define SECURE_QKD_INGEST_DISCARD 2u

#define SECURE_QKD_OK             0u
#define SECURE_QKD_ERR            1u
#define SECURE_QKD_OVERFLOW       2u
#define SECURE_QKD_PARSE          3u

void secure_qkd_discard(void);
uint32_t secure_qkd_ingest(const uint8_t *chunk, uint32_t len, uint32_t flags,
                           uint32_t *countOut);

#endif /* SECURE_QKD_INGEST_H */
