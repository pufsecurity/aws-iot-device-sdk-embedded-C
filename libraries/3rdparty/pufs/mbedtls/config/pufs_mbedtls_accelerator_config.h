/*
 * Copyright (c) 2023-2024, PUFsecurity. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef PUFS_MBEDTLS_ACCELERATOR_CONF_H
#define PUFS_MBEDTLS_ACCELERATOR_CONF_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


//////* Main Config */

#define MBEDTLS_SHA256_ALT
#define MBEDTLS_ECDSA_VERIFY_ALT
#define MBEDTLS_GCM_ALT


// MBEDTLS_ECDH_GEN_PUBLIC_ALT and MBEDTLS_ECDH_COMPUTE_SHARED_ALT
// should be defined at the same time if ECDH alternative is enabled.
// private key (d) is used to store the using key slot
// (the key is generated by mbedtls_ecdh_gen_public)
#define MBEDTLS_ECDH_GEN_PUBLIC_ALT
#define MBEDTLS_ECDH_COMPUTE_SHARED_ALT

#if ((defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT) && !defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)) || \
     (!defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT) && defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)))

#error "MBEDTLS_ECDH_GEN_PUBLIC_ALT and MBEDTLS_ECDH_COMPUTE_SHARED_ALT should be defined at the same time."
#endif




#if defined(PUFSE_HOST) && defined(MBEDTLS_SHA256_ALT)
//TLS PRF, calculation and update checksum alternative
#define MBEDTLS_PUFS_TLS_PRF_CALC_ALT
#endif

//TLS RNG Alternative
#define MBEDTLS_PUFS_TLS_RNG_ALT


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PUFS_MBEDTLS_ACCELERATOR_CONF_H */
