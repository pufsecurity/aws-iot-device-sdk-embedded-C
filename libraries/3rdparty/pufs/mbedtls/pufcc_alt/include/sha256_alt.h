/*
 * Copyright (c) 2023-2024, PUFsecurity. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SHA256_ALT_H
#define SHA256_ALT_H

#include <stddef.h>
#include <stdint.h>
#include "common_alt.h"
#include "pufs_hmac_internal.h"
#include "pufs_hmac.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * \brief          The SHA-256 context structure.
 *
 *                 The structure is used for SHA-256
 *                 checksum calculations.
 */

#define HASH_CTX_SIZE_IN_BYTES  sizeof(pufs_hash_ctx)
typedef struct mbedtls_sha256_context
{

    uint8_t buff[HASH_CTX_SIZE_IN_BYTES];  /*! Internal buffer */

} mbedtls_sha256_context;


#ifdef __cplusplus
}
#endif

#endif /* SHA256_ALT_H */
