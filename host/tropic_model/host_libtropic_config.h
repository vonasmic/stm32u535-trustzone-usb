/**
 * @file    host_libtropic_config.h
 * @brief   Host-model overrides (prod0 SH0 via SE_TROPIC_SH0_PROD, small PIN budget)
 *
 * Forced in with -include before firmware headers. Do not include from Secure/.
 */
#ifndef HOST_LIBTROPIC_CONFIG_H
#define HOST_LIBTROPIC_CONFIG_H

#ifndef SE_TROPIC_SH0_PROD
#define SE_TROPIC_SH0_PROD
#endif
/* Keep the model's attempt budget small; firmware defaults higher on silicon. */
#define SE_TROPIC_PIN_ROUNDS 4u

#endif /* HOST_LIBTROPIC_CONFIG_H */
