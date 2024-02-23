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
 *@file        pufs_mbedtls_gcm.c
 *
 *@brief       Pufsecurity crypto implmentation for gcm
 *
 *             References:
 *
 *             https://csrc.nist.gov/publications/detail/sp/800-38d/final
 *             https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
 *             See also:
 *             https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
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
#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif


#include <string.h>

#if defined(MBEDTLS_AESNI_C)
#include "mbedtls/aesni.h"
#endif



#if defined(MBEDTLS_GCM_ALT)

#include "pufs_mbedtls_gcm.h"
#include "pufs_common.h"

#include "pufs_sp38d.h"


#define IS_GCM_ENCRPTED(ctx) \
    (((ctx->mode) == MBEDTLS_GCM_ENCRYPT)?1:0)


/* GCM_DATA_CIPHER_DEBUG
 * enable to print data enc/dec length
 */
//#define GCM_DATA_CIPHER_DEBUG

/* GCM_ONE_FUNC
 * enable : call pufs_enc_gcm/pufs_dec_gcm
 * not defined, call iuf func seperately
 */
//#define GCM_ONE_FUNC


/**
 * Base gcm init and update information.
 * (Only init and update function are defined,
 *  because parmaeter types are different in enc and dec functions.)
 */
typedef struct pufs_gcm_iu_func_base
{

    /* Init Function */
    pufs_status_t (*pufs_gcm_init)(pufs_sp38d_ctx *sp38d_ctx,
                                   pufs_cipher_t cipher,
                                   pufs_key_type_t keytype,
                                   size_t keyaddr,
                                   uint32_t keybits,
                                   const uint8_t *iv,
                                   uint32_t ivlen);
    /* Update Function */
    pufs_status_t (*pufs_gcm_update)(pufs_sp38d_ctx *sp38d_ctx,
                                     uint8_t *out,
                                     uint32_t *outlen,
                                     const uint8_t *in,
                                     uint32_t inlen);

} pufs_gcm_iu_func_base_t;


//note enc final tag ins not const unit8_t
static const pufs_gcm_iu_func_base_t gcm_enc_func =
{

    _pufs_enc_gcm_init,
    pufs_enc_gcm_update
};



static const pufs_gcm_iu_func_base_t gcm_dec_func =
{

    _pufs_dec_gcm_init,
    pufs_dec_gcm_update
};


/*
 * Initialize a context
 */
void pufs_mbedtls_gcm_init( mbedtls_gcm_context *ctx )
{

    pufs_sp38d_ctx *sp38d_ctx = NULL;

    memset( ctx, 0, sizeof( mbedtls_gcm_context ) );

    sp38d_ctx = (pufs_sp38d_ctx *)(ctx->buff);
    sp38d_ctx->op = SP38D_AVAILABLE;
}

int pufs_mbedtls_cipher_setkey( mbedtls_gcm_context *gcm_ctx,
                                mbedtls_cipher_context_t *ctx, const unsigned char *key,
                                int key_bitlen, const mbedtls_operation_t operation )
{

    int ret = 0;

    PUFS_LOG_FUNC("pufs_mbedtls_cipher_setkey \n");

    if ( NULL == ctx || NULL == ctx->cipher_info )
    {
        PUFS_LOG_ERR("pufs_mbedtls_cipher_setkey error - null ctx\n");
        ret = MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        goto exit;
    }

    if ( ( ctx->cipher_info->flags & MBEDTLS_CIPHER_VARIABLE_KEY_LEN ) == 0 &&
         (int) ctx->cipher_info->key_bitlen != key_bitlen )
    {

        PUFS_LOG_ERR("pufs_mbedtls_cipher_setkey error - inconsistent key bitlen:%d/%d\n", ctx->cipher_info->key_bitlen,
                     key_bitlen);
        ret = MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        goto exit;
    }

    ctx->key_bitlen = key_bitlen;
    ctx->operation = operation;

    /*
     * For OFB, CFB and CTR mode always use the encryption key schedule
     */
    if ( MBEDTLS_ENCRYPT == operation ||
         MBEDTLS_MODE_CFB == ctx->cipher_info->mode ||
         MBEDTLS_MODE_OFB == ctx->cipher_info->mode ||
         MBEDTLS_MODE_CTR == ctx->cipher_info->mode )
    {

        memcpy(gcm_ctx->key, key, key_bitlen / 8);
        gcm_ctx->keybits = key_bitlen;
        ret = 0;
        goto exit;
    }

    if ( MBEDTLS_DECRYPT == operation )
    {
        memcpy(gcm_ctx->key, key, key_bitlen / 8);
        gcm_ctx->keybits = key_bitlen;
        ret = 0;
        goto exit;
    }

exit:
    if (ret != 0)
    {
        PUFS_LOG_ERR("pufs_mbedtls_cipher_setkey failed ret :%d\n", ret);
    }

    return ( ret );
}


int pufs_mbedtls_gcm_setkey( mbedtls_gcm_context *ctx,
                             mbedtls_cipher_id_t cipher,
                             const unsigned char *key,
                             unsigned int keybits )
{
    int ret;
    const mbedtls_cipher_info_t *cipher_info;

    PUFS_LOG_FUNC("pufs_mbedtls_gcm_setkey \n");

    cipher_info = mbedtls_cipher_info_from_values( cipher, keybits, MBEDTLS_MODE_ECB );
    if ( cipher_info == NULL )
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_setkey error - null cipher info\n");
        ret = MBEDTLS_ERR_GCM_BAD_INPUT;
        goto exit;
    }

    if ( cipher_info->block_size != 16 )
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_setkey error - block size!=16 (%d)\n", cipher_info->block_size);
        ret = MBEDTLS_ERR_GCM_BAD_INPUT;
        goto exit;
    }

    mbedtls_cipher_free( &ctx->cipher_ctx );

    if ( ( ret = mbedtls_cipher_setup( &ctx->cipher_ctx, cipher_info ) ) != 0 )
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_setkey error - mbedtls_cipher_setup error ret:%d\n", ret);
        goto exit;
    }

    if ( ( ret = pufs_mbedtls_cipher_setkey( ctx, &ctx->cipher_ctx, key, keybits,
                                             MBEDTLS_ENCRYPT ) ) != 0 )
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_setkey error - pufs_mbedtls_cipher_setkey error ret:%d\n", ret);
        goto exit;
    }

exit:
    if (ret != 0)
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_setkey failed ret:%d\n", ret);
    }

    return ( ret );
}

/* use for gcm_start*/
int pufs_mbedtls_gcm_reset_data_ctx( mbedtls_gcm_context *ctx)
{
    ctx->output_addr = 0;
    ctx->len = 0;
    ctx->add_len = 0;
    PUFS_LOG_FUNC("pufs_mbedtls_gcm_reset_data_ctx\n");

    return 0;

}


int pufs_mbedtls_gcm_starts( mbedtls_gcm_context *ctx,
                             int mode,
                             const unsigned char *iv,
                             size_t iv_len,
                             const unsigned char *add,
                             size_t add_len )
{
    int ret = 0;
    pufs_status_t status = SUCCESS;
    pufs_sp38d_ctx *sp38d_ctx = NULL;
    pufs_cipher_t  pufs_cipher = N_CIPHER_T;
    const mbedtls_cipher_info_t  *p_mbed_cipher_info = NULL;

    size_t   keyaddr = 0;
    uint32_t keybits = 0;
    const pufs_gcm_iu_func_base_t *p_gcm_func = NULL;

    PUFS_LOG_FUNC("pufs_mbedtls_gcm_starts\n");


    //check context
    if (ctx == NULL)
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_starts error - NULL context\n");
        ret = MBEDTLS_ERR_GCM_BAD_INPUT;
        goto exit;
    }
    else
    {
        sp38d_ctx = (pufs_sp38d_ctx *)(ctx->buff);
    }

    if (ctx->cipher_ctx.cipher_info == NULL)
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_starts error - NULL cipher info context\n");
        ret = MBEDTLS_ERR_GCM_BAD_INPUT;
        goto exit;
    }
    else
    {
        p_mbed_cipher_info = (ctx->cipher_ctx.cipher_info);
    }

    /* IV and AD are limited to 2^64 bits, so 2^61 bytes */
    /* IV is not allowed to be zero length */
    if ( iv_len == 0 ||
         ( (uint64_t) iv_len  ) >> 61 != 0 ||
         ( (uint64_t) add_len ) >> 61 != 0 )
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_starts error - iv_len:%d or add_len:%d error\n", iv_len, add_len);
        ret = MBEDTLS_ERR_GCM_BAD_INPUT;
        goto exit;
    }

    pufs_mbedtls_gcm_reset_data_ctx(ctx);


    if (((p_mbed_cipher_info->type) < MBEDTLS_CIPHER_AES_128_GCM) &&
        ((p_mbed_cipher_info->type) > MBEDTLS_CIPHER_AES_256_GCM))
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_starts error - cipher type error:%d\n",
                     p_mbed_cipher_info->type);
        ret = MBEDTLS_ERR_GCM_BAD_INPUT;
        goto exit;

    }
    else
    {
        pufs_cipher = AES;
    }

    ctx->len = 0;
    ctx->add_len = 0;
    ctx->mode = mode;

    if (mode == MBEDTLS_GCM_ENCRYPT)
    {
        p_gcm_func = &gcm_enc_func;
    }
    else
    {
        p_gcm_func = &gcm_dec_func;
    }

    keyaddr = (size_t)(ctx->key);
    keybits = ctx->keybits;

    status = p_gcm_func->pufs_gcm_init(sp38d_ctx, pufs_cipher, SWKEY,  keyaddr, keybits, iv, iv_len);


    if (status != SUCCESS )
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_starts error - init failed status:%d\n", status);
        ret = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
        goto exit;
    }

    //Update additional authentication data
    status = p_gcm_func->pufs_gcm_update(sp38d_ctx, NULL, NULL, add, add_len);

    if (status != SUCCESS )
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_starts error - add update failed status:%d\n", status);
        ret = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
        goto exit;

    }
    ctx->add_len = add_len;

exit:
    if (ret != 0)
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_starts failed ret: %d\n", ret);
    }
    return ( ret );
}

int pufs_mbedtls_gcm_update( mbedtls_gcm_context *ctx,
                             size_t length,
                             const unsigned char *input,
                             unsigned char *output )
{
    int ret = 0;
    pufs_status_t status = SUCCESS;
    pufs_sp38d_ctx *sp38d_ctx = NULL;
    uint32_t toutlen = 0;
    const pufs_gcm_iu_func_base_t *p_gcm_func = NULL;

    PUFS_LOG_FUNC("pufs_mbedtls_gcm_update\n");

    //check context
    if (ctx == NULL)
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_update error - NULL context\n");
        ret = MBEDTLS_ERR_GCM_BAD_INPUT;
        goto exit;
    }
    else
    {
        sp38d_ctx = (pufs_sp38d_ctx *)(ctx->buff);
    }

    if ( (output > input) && (((size_t) ( output - input )) < length) )
    {

        PUFS_LOG_ERR("pufs_mbedtls_gcm_update error - incorrect length. length:%d, input:%p, output:%p\n",
                     length, input, output);
        ret = MBEDTLS_ERR_GCM_BAD_INPUT;
        goto exit;

    }

    //Initilize output buffer address when outaddr == 0
    if (ctx->output_addr == 0)
    {
        ctx->output_addr = output;
    }

    /* Total length is restricted to 2^39 - 256 bits, ie 2^36 - 2^5 bytes
     * Also check for possible overflow */
    if ( ((ctx->len + length) < ctx->len) ||
         ((uint64_t) (ctx->len + length) > 0xFFFFFFFE0ull) )
    {
        ret = MBEDTLS_ERR_GCM_BAD_INPUT;
        goto exit;
    }

    if (ctx->mode == MBEDTLS_GCM_ENCRYPT)
    {
        p_gcm_func = &gcm_enc_func;
    }
    else
    {
        p_gcm_func = &gcm_dec_func;
    }

    status = p_gcm_func->pufs_gcm_update(sp38d_ctx, output, &toutlen, input, length);

    if (status != SUCCESS )
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_update error - update failed status:%d \n", status);
        ret = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
        goto exit;
    }


#ifdef GCM_DATA_CIPHER_DEBUG
    PUFS_LOG_INF("pufs_mbedtls_gcm_update toutlen:%d, length:%d ctx->output_addr (orig:%p / ", toutlen, length,
                 ctx->output_addr);
#endif

    ctx->output_addr =  ctx->output_addr + toutlen;


#ifdef GCM_DATA_CIPHER_DEBUG
    PUFS_LOG_INF("after:%p )\n", ctx->output_addr);
#endif

    ctx->len += length;

exit:
    if (ret != 0)
    {
        PUFS_LOG_ERR("pufs_enc_gcm_update failed ret:%d, status:%d\n", ret, status);
    }

    return ret;

}

int pufs_mbedtls_gcm_finish( mbedtls_gcm_context *ctx,
                             unsigned char *tag,
                             size_t tag_len )
{
    uint64_t orig_len = ctx->len * 8;
    uint64_t orig_add_len = ctx->add_len * 8;
    int ret = 0;
    pufs_status_t status = SUCCESS;
    pufs_sp38d_ctx *sp38d_ctx = NULL;
    uint32_t toutlen = 0;
    uint8_t *p_out = NULL;  //pointer to output buffer in ctx

    PUFS_LOG_FUNC("pufs_mbedtls_gcm_finish\n");

    if ( tag_len > 16 || tag_len < 4 )
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_finish error - invalid tag_len:%d\n", tag_len);
        ret = MBEDTLS_ERR_GCM_BAD_INPUT;
        goto exit;
    }

    //check context
    if (ctx == NULL)
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_finish error - NULL context\n");
        ret = MBEDTLS_ERR_GCM_BAD_INPUT;
        goto exit;
    }
    else
    {
        sp38d_ctx = (pufs_sp38d_ctx *)(ctx->buff);
    }

    if ( orig_len || orig_add_len )
    {
        p_out = ctx->output_addr;

        if (IS_GCM_ENCRPTED(ctx))
        {
            status = pufs_enc_gcm_final(sp38d_ctx, p_out, &toutlen, tag, tag_len);
        }
        else
        {
            status = pufs_dec_gcm_final(sp38d_ctx, p_out, &toutlen, tag, tag_len);
        }

#ifdef GCM_DATA_CIPHER_DEBUG
        PUFS_LOG_INF("pufs_mbedtls_gcm_finish toutlen:%d p_out:%p\n", toutlen, p_out);
#endif

        if (status != SUCCESS )
        {
            PUFS_LOG_ERR("pufs_mbedtls_gcm_finish (enc:%d) error - final failed status:%d \n", IS_GCM_ENCRPTED(ctx), status);
            ret = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
            goto exit;
        }

    }

exit:
    if (ret != 0)
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_finish failed ret:%d, status:%d\n", ret, status);
    }

    return ( ret );
}


int pufs_mbedtls_gcm_crypt_and_tag( mbedtls_gcm_context *ctx,
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
    int ret = 0;

#ifdef GCM_ONE_FUNC
    pufs_status_t status = SUCCESS;
    uint32_t outlen = 0;

    PUFS_LOG_FUNC("pufs_mbedtls_gcm_crypt_and_tag - pufs_enc_gcm\n");
    PUFS_MBEDTLS_UNUSED(mode);

    status = pufs_enc_gcm(output, &outlen, input, length, AES, SWKEY,  ctx->key, ctx->keybits,
                          iv, iv_len, add, add_len, tag, tag_len);

    if (status != SUCCESS)
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_crypt_and_tag - pufs_enc_gcm failed:%d\n", status);
        ret = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
        goto exit;
    }

#else

    PUFS_LOG_FUNC("pufs_mbedtls_gcm_crypt_and_tag - iuf \n");

    if ( ( ret = pufs_mbedtls_gcm_starts( ctx, mode, iv, iv_len, add, add_len ) ) != 0 )
    {
        goto exit;
    }

    if ( ( ret = pufs_mbedtls_gcm_update( ctx, length, input, output ) ) != 0 )
    {
        goto exit;
    }

    if ( ( ret = pufs_mbedtls_gcm_finish( ctx, tag, tag_len ) ) != 0 )
    {
        goto exit;
    }

#endif

exit:
    if (ret != 0)
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_crypt_and_tag failed ret:%d\n", ret);
    }

    return ret;

}

int pufs_mbedtls_gcm_auth_decrypt( mbedtls_gcm_context *ctx,
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
    int ret = 0;

#ifdef GCM_ONE_FUNC
    pufs_status_t status = SUCCESS;
    uint32_t outlen = 0;


    PUFS_LOG_FUNC("pufs_mbedtls_gcm_auth_decrypt - pufs_dec_gcm\n");
    status = pufs_dec_gcm( output, &outlen, input, length, AES, SWKEY, ctx->key, ctx->keybits,
                           iv, iv_len, add, add_len, (unsigned char *)tag, tag_len);
    if (status != SUCCESS)
    {
        printf("pufs_mbedtls_gcm_auth_decrypt error - pufs_dec_gcm failed:%d\n ", status);
        ret = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
        goto exit;
    }

#else
    PUFS_LOG_FUNC("pufs_mbedtls_gcm_auth_decrypt - iuf\n");

    if ( ( ret = pufs_mbedtls_gcm_crypt_and_tag( ctx, MBEDTLS_GCM_DECRYPT, length,
                                                 iv, iv_len, add, add_len,
                                                 input, output, tag_len, (unsigned char *)tag ) ) != 0 )
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_auth_decrypt error - crypt_and_tag failed ret:%d\n", ret);
        goto exit;
    }

#endif
exit:
    if (ret != 0)
    {
        PUFS_LOG_ERR("pufs_mbedtls_gcm_auth_decrypt failed ret:%d\n", ret);
    }

    return ret;

}

void pufs_mbedtls_gcm_free( mbedtls_gcm_context *ctx )
{

    PUFS_LOG_FUNC("pufs_mbedtls_gcm_free \n");

    if (ctx == NULL)
        return;

    mbedtls_cipher_free( &(ctx->cipher_ctx));
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_gcm_context ) );

}
#endif /* MBEDTLS_GCM_ALT */

#endif /* MBEDTLS_GCM_C */
