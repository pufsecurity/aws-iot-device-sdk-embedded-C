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
 *@file        pufs_mbedtls_sha256.c
 *
 *@brief       FIPS-180-2 compliant SHA-256 implementation
 *
 *             The SHA-256 Secure Hash Standard was published by NIST in 2002.
 *             http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
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
//#include "pufs_mbedtls_sha256.h"

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

void pufs_mbedtls_sha256_init( mbedtls_sha256_context *ctx )
{
    PUFS_LOG_SHA_FUNC("pufs_mbedtls_sha256_init\n");
    memset( ctx, 0, sizeof( mbedtls_sha256_context ) );
}

void pufs_mbedtls_sha256_free( mbedtls_sha256_context *ctx )
{
    PUFS_LOG_SHA_FUNC("pufs_mbedtls_sha256_free\n");

    if ( ctx == NULL )
        return;

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_sha256_context ) );
}

void pufs_mbedtls_sha256_clone( mbedtls_sha256_context *dst,
                                const mbedtls_sha256_context *src )
{
    PUFS_LOG_FUNC("pufs_mbedtls_sha256_clone\n");

    *dst = *src;
}

/*
 * SHA-256 context setup
 */
int pufs_mbedtls_sha256_starts_ret( mbedtls_sha256_context *ctx, int is224 )
{


    pufs_status_t status = SUCCESS;
    pufs_hash_t hash = N_HASH_T;
    pufs_hash_ctx *hash_ctx = NULL;

    PUFS_LOG_SHA_FUNC("pufs_mbedtls_sha256_starts_ret\n");

    if (ctx == NULL)
    {
        PUFS_LOG_ERR("pufs_mbedtls_sha256_starts_ret error - NULL context\n");
        return 1;
    }
    else
    {
        hash_ctx = (pufs_hash_ctx *)ctx->buff;
    }

    if (is224 == 1)
    {
        hash = SHA_224;
    }
    else
    {
        hash = SHA_256;
    }

    hash_ctx->op = HMAC_AVAILABLE;
    status =  pufs_hash_init(hash_ctx, hash);

    if (status != SUCCESS)
    {
        PUFS_LOG_ERR("pufs_mbedtls_sha256_starts_ret error - hash_init error :%d\n", status);
        return 1;
    }
    else
    {
        return 0;
    }

}


/*
 * SHA-256 process buffer
 */
int pufs_mbedtls_sha256_update_ret( mbedtls_sha256_context *ctx,
                                    const unsigned char *input,
                                    size_t ilen )
{
    pufs_hash_ctx *hash_ctx;
    pufs_status_t status = SUCCESS;

    PUFS_LOG_SHA_FUNC("pufs_mbedtls_sha256_update_ret \n");

    if (ctx == NULL)
    {
        PUFS_LOG_ERR("pufs_mbedtls_sha256_update_ret error: null ctx\n");
        return 1;
    }
    else
    {
        hash_ctx = (pufs_hash_ctx *)(ctx->buff);
    }

#if 1
    if (ilen > 65535) //to do
    {
        PUFS_LOG_ERR("pufs_mbedtls_sha256_update_ret error : ilen (%d) > 65535\n", ilen);
        return 1;
    }
#endif

    if ((status = pufs_hash_update(hash_ctx, input, ilen)) != SUCCESS)
    {
        PUFS_LOG_ERR("pufs_mbedtls_sha256_update_ret error: hash update failed, input:%p, ilen:%d\n",
                     input, ilen);
        return 1;
    }

    return 0;
}


/*
 * SHA-256 final digest
 */
int pufs_mbedtls_sha256_finish_ret( mbedtls_sha256_context *ctx,
                                    unsigned char output[32] )
{
    pufs_hash_ctx *hash_ctx;
    pufs_status_t status = SUCCESS;
    pufs_dgst_st md;

    //int ret;
    //to do
    PUFS_LOG_SHA_FUNC("pufs_mbedtls_sha256_finish_ret \n");


    if (ctx == NULL)
    {
        PUFS_LOG_ERR("pufs_mbedtls_sha256_update_ret error: null ctx\n");
        return 1;
    }
    else
    {
        hash_ctx = (pufs_hash_ctx *)(ctx->buff);
    }

    memset(output, 0, 32);
    memset(&md, 0, sizeof(pufs_dgst_st));


    status = pufs_hash_final(hash_ctx, &md);
    if (status != SUCCESS)
    {
        PUFS_LOG_ERR("pufs_mbedtls_sha256_update_ret error: pufs_hash_final error :%d\n", status);
        return 1;
    }
    else
    {
        memcpy(output, md.dgst, md.dlen);
        return 0;
    }
}


#endif /* MBEDTLS_SHA256_ALT */


#endif /* PUFS_MBEDTLS_SHA256_C */
