/**
 * @file    host_tropic.h
 * @brief   Host-only Tropic TCP model knobs for se_host
 */
#ifndef HOST_TROPIC_H
#define HOST_TROPIC_H

#ifdef __cplusplus
extern "C" {
#endif

/** Default TROPIC01 model_server port (libtropic POSIX TCP HAL). */
#define HOST_TROPIC_DEFAULT_PORT 28992u

/** Use before firmware attach. 0 keeps HOST_TROPIC_DEFAULT_PORT. */
void host_tropic_set_port(unsigned port);

#ifdef __cplusplus
}
#endif

#endif /* HOST_TROPIC_H */
