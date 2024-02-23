/***********************************************************************************
 *
 *  Copyright (c) 2023-2024, PUFsecurity
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *  3. Neither the name of PUFsecurity nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 *  OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 *  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **************************************************************************************/


/*!*************************************************************************************
 *
 *@file        pufs_mbedtls_sha256.h
 *
 *@brief       This file contains PUFSecurity Crypto SHA-256 definitions and functions for mbedtls.
 *
 *             The Secure Hash Algorithms 224 and 256 (SHA-224 and SHA-256) cryptographic
 *             hash functions are defined in <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
 *
 *@copyright   2023-2024 PUFsecurity
 *
 ***************************************************************************************/


#ifndef PUFS_MBEDTLS_SHA256_H
#define PUFS_MBEDTLS_SHA256_H


#include <stddef.h>
#include <stdint.h>

#include "sha256_alt.h"


#ifdef __cplusplus
extern "C" {
#endif



/**
 * \brief          This function initializes a PUFSecurity Crypto SHA-256 context.
 *
 * \param ctx      The PUFSecurity Crypto  SHA-256 context to initialize.
 */
void pufs_mbedtls_sha256_init( mbedtls_sha256_context *ctx );

/**
 * \brief          This function clears a PUFSecurity Crypto SHA-256 context.
 *
 * \param ctx      The PUFSecurity Crypto SHA-256 context to clear.
 */
void pufs_mbedtls_sha256_free( mbedtls_sha256_context *ctx );

/**
 * \brief          This function clones the state of a PUFSecurity Crypto  SHA-256 context.
 *
 * \param dst      The destination context.
 * \param src      The context to clone.
 */
void pufs_mbedtls_sha256_clone( mbedtls_sha256_context *dst,
                                const mbedtls_sha256_context *src );


/**
 * \brief          This function starts a PUFSecurity Crypto  SHA-224 or SHA-256 checksum
 *                 calculation.
 *
 * \param ctx      The context to initialize.
 * \param is224    Determines which function to use:
 *                 0: Use SHA-256, or 1: Use SHA-224.
 *
 * \return         \c 0 on success, 1 on failure
 */
int pufs_mbedtls_sha256_starts_ret( mbedtls_sha256_context *ctx, int is224 );


/**
 * \brief          This function feeds an input buffer into an ongoing
 *                 PUFSecurity Crypto SHA-256 checksum calculation.
 *
 * \param ctx      The SHA-256 context.
 * \param input    The buffer holding the data.
 * \param ilen     The length of the input data.
 *
 * \return         \c 0 on success, 1 on failure
 */
int pufs_mbedtls_sha256_update_ret( mbedtls_sha256_context *ctx,
                                    const unsigned char *input,
                                    size_t ilen );

/**
 * \brief          This function finishes the PUFSecurity Crypto SHA-256 operation, and writes
 *                 the result to the output buffer.
 *
 * \param ctx      The SHA-256 context.
 * \param output   The SHA-224 or SHA-256 checksum result.
 *
 * \return         \c 0 on success, 1 on failure.
 */
int pufs_mbedtls_sha256_finish_ret( mbedtls_sha256_context *ctx,
                                    unsigned char output[32] );

#ifdef __cplusplus
}
#endif

#endif /* pufs_mbedtls_sha256.h */
