/**
 * @file    secure_stream.h
 * @brief   Generic byte-stream write callback for protocol encoders
 */
#ifndef SECURE_STREAM_H
#define SECURE_STREAM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Write @p len bytes from @p data; return 0 on success, -1 on failure.
 * @p ctx is opaque caller state forwarded unchanged from the API that invoked
 * the callback (e.g. a TLS session handle or test output buffer).
 */
typedef int (*secure_stream_write_fn)(const uint8_t *data, uint32_t len, void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_STREAM_H */
