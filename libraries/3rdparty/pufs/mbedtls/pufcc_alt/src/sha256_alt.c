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
 *@file        sha256_alt.c
 *
 *@brief       sha256 alternative wrapper functions for FIPS-180-2 compliant SHA-256 implementation
 *
 *@copyright   2023-2024 PUFsecurity
 *
 ***************************************************************************************/


#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SHA256_C)

#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf printf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#if defined(MBEDTLS_SHA256_ALT)
#include "pufs_mbedtls_sha256.h"

void mbedtls_sha256_init( mbedtls_sha256_context *ctx )
{
    PUFS_LOG_WRAP_FUNC("pufs mbedtls_sha256_init wrapper \n");

    pufs_mbedtls_sha256_init(ctx);
}

void mbedtls_sha256_free( mbedtls_sha256_context *ctx )
{
    PUFS_LOG_WRAP_FUNC("pufs mbedtls_sha256_free wrapper \n");

    if ( ctx == NULL )
        return;

    pufs_mbedtls_sha256_free(ctx);
}

void mbedtls_sha256_clone( mbedtls_sha256_context *dst,
                           const mbedtls_sha256_context *src )
{
    pufs_mbedtls_sha256_clone(dst, src);
}

/*
 * SHA-256 context setup
 */
int mbedtls_sha256_starts_ret( mbedtls_sha256_context *ctx, int is224 )
{

    PUFS_LOG_WRAP_FUNC("pufs mbedtls_sha256_starts_ret wrapper \n");

    pufs_mbedtls_sha256_starts_ret(ctx, is224);
    return ( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha256_starts( mbedtls_sha256_context *ctx,
                            int is224 )
{
    PUFS_LOG_WRAP_FUNC("pufs mbedtls_sha256_starts wrapper \n");
    pufs_mbedtls_sha256_starts_ret( ctx, is224 );
}
#endif

int mbedtls_internal_sha256_process( mbedtls_sha256_context *ctx,
                                     const unsigned char data[64] )
{

    int ret;
    PUFS_LOG_WRAP_FUNC("pufs mbedtls_internal_sha256_process wrapper \n");

    //to check
    ret = pufs_mbedtls_sha256_update_ret(ctx, data, 64);
    return ret;

}

/*
 * SHA-256 process buffer
 */
int mbedtls_sha256_update_ret( mbedtls_sha256_context *ctx,
                               const unsigned char *input,
                               size_t ilen )
{
    int ret;
    PUFS_LOG_WRAP_FUNC("pufs mbedtls_sha256_update_ret wrapper \n");

    ret = pufs_mbedtls_sha256_update_ret(ctx, input, ilen);
    return ret;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha256_update( mbedtls_sha256_context *ctx,
                            const unsigned char *input,
                            size_t ilen )
{
    mbedtls_sha256_update_ret( ctx, input, ilen );
}
#endif

/*
 * SHA-256 final digest
 */
int mbedtls_sha256_finish_ret( mbedtls_sha256_context *ctx,
                               unsigned char output[32] )
{

    int ret;

    PUFS_LOG_WRAP_FUNC("pufs mbedtls_sha256_finish_ret wrapper \n");
    ret = pufs_mbedtls_sha256_finish_ret(ctx, output);
    return ret;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha256_finish( mbedtls_sha256_context *ctx,
                            unsigned char output[32] )
{
    mbedtls_sha256_finish_ret( ctx, output );
}
#endif

#endif /* MBEDTLS_SHA256_ALT */

#endif /* MBEDTLS_SHA256_C */
