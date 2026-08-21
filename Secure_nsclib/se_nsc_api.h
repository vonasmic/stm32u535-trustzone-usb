/**
 * @file    se_nsc_api.h
 * @brief   CMSE non-secure-callable attribute for Secure NSC veneers
 */
#ifndef SE_NSC_API_H
#define SE_NSC_API_H

#if defined(__GNUC__) && defined(__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE == 3U)
#define CSME_NSE_API __attribute__((cmse_nonsecure_entry))
#else
#define CSME_NSE_API
#endif

#endif /* SE_NSC_API_H */
