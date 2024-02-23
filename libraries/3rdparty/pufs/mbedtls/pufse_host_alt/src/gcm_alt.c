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
 *@file        gcm_alt.c
 *
 *@brief       gcm alternative wrapper functions
 *
 *             References:
 *             https://csrc.nist.gov/publications/detail/sp/800-38d/final
 *             https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
 *             See also:
 *             https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
 *
 *
 *@copyright   2023-2024 PUFsecurity
 *
 ***************************************************************************************/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_GCM_C)

#include "mbedtls/gcm.h"
#include "pufs_mbedtls_gcm.h"


#if defined(MBEDTLS_GCM_ALT)

/*
 * Initialize a context
 */
void mbedtls_gcm_init( mbedtls_gcm_context *ctx )
{

    PUFS_LOG_WRAP_FUNC("pufs mbedtls_gcm_init wrapper \n");

    pufs_mbedtls_gcm_init(ctx);
}


int mbedtls_gcm_setkey( mbedtls_gcm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits )
{
    int ret;

    PUFS_LOG_WRAP_FUNC("pufs mbedtls_gcm_setkey wrapper \n");

    ret = pufs_mbedtls_gcm_setkey(ctx, cipher, key, keybits);

    return (ret);

}

int mbedtls_gcm_starts( mbedtls_gcm_context *ctx,
                        int mode,
                        const unsigned char *iv,
                        size_t iv_len,
                        const unsigned char *add,
                        size_t add_len )
{
    int ret;

    PUFS_LOG_WRAP_FUNC("pufs mbedtls_gcm_starts wrapper \n");

    ret = pufs_mbedtls_gcm_starts(ctx, mode, iv, iv_len, add, add_len);

    return (ret);
}


int mbedtls_gcm_update( mbedtls_gcm_context *ctx,
                        size_t length,
                        const unsigned char *input,
                        unsigned char *output )
{
    int ret;

    PUFS_LOG_WRAP_FUNC("pufs mbedtls_gcm_update wrapper \n");

    ret = pufs_mbedtls_gcm_update(ctx, length, input, output);

    return (ret);
}

int mbedtls_gcm_finish( mbedtls_gcm_context *ctx,
                        unsigned char *tag,
                        size_t tag_len )
{
    int ret;

    PUFS_LOG_WRAP_FUNC("pufs mbedtls_gcm_finish wrapper \n");

    ret = pufs_mbedtls_gcm_finish(ctx, tag, tag_len);

    return (ret);
}

int mbedtls_gcm_crypt_and_tag( mbedtls_gcm_context *ctx,
                               int mode,
                               size_t length,
                               const unsigned char *iv,
                               size_t iv_len,
                               const unsigned char *add,
                               size_t add_len,
                               const unsigned char *input,
                               unsigned char *output,
                               size_t tag_len,
                               unsigned char *tag )
{
    int ret;

    PUFS_LOG_WRAP_FUNC("pufs mbedtls_gcm_crypt_and_tag wrapper \n");

    ret = pufs_mbedtls_gcm_crypt_and_tag(ctx, mode, length, iv, iv_len,
                                         add, add_len, input, output, tag_len, tag);

    return (ret);

}

int mbedtls_gcm_auth_decrypt( mbedtls_gcm_context *ctx,
                              size_t length,
                              const unsigned char *iv,
                              size_t iv_len,
                              const unsigned char *add,
                              size_t add_len,
                              const unsigned char *tag,
                              size_t tag_len,
                              const unsigned char *input,
                              unsigned char *output )
{

    int ret;

    PUFS_LOG_WRAP_FUNC("pufs mbedtls_gcm_auth_decrypt wrapper \n");

    ret = pufs_mbedtls_gcm_auth_decrypt(ctx, length, iv, iv_len,
                                        add, add_len, tag, tag_len, input, output);

    return (ret);

}

void mbedtls_gcm_free( mbedtls_gcm_context *ctx )
{
    PUFS_LOG_WRAP_FUNC("pufs mbedtls_gcm_free wrapper \n");

    pufs_mbedtls_gcm_free(ctx);
}

#endif /* !MBEDTLS_GCM_ALT */

#endif /* MBEDTLS_GCM_C */
