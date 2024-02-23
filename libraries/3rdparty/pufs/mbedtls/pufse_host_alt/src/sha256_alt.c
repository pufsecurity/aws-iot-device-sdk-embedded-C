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

//#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf printf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif /* MBEDTLS_PLATFORM_C */
//#endif /* MBEDTLS_SELF_TEST */

#if defined(MBEDTLS_SHA256_ALT)
#include "pufs_mbedtls_sha256.h"

uint8_t g_sha_log = 1;

//internal function declaration
int mbedtls_msg_node_lst_free(t_msg_node_list *list);
t_msg_node *mbedtls_msg_node_alloc(uint32_t len, uint8_t *msg);



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

    if (ctx->tls_msg_list.node_count != 0)
    {
        mbedtls_msg_node_lst_free(&(ctx->tls_msg_list));
    }

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

#if 1//MBEDTLS_PUFS_TLS_PRF_CALC_ALT
t_msg_node *mbedtls_msg_node_alloc(uint32_t len, uint8_t *msg)
{
    t_msg_node *msg_node = NULL;
    uint8_t *msg_buf = NULL;

    if (len == 0)
    {
        PUFS_LOG_ERR("msg node len = 0");
        return NULL;
    }

    msg_node = mbedtls_calloc(1, sizeof(t_msg_node));

    if (msg_node == NULL)
    {
        PUFS_LOG_ERR("Allocate msg node failed");
        return NULL;
    }

    msg_buf = mbedtls_calloc(1, len);
    if (msg_buf == NULL)
    {
        PUFS_LOG_ERR("Allocate msg node failed len:%d");
        mbedtls_free(msg_node);
        return NULL;
    }

    memcpy(msg_buf, msg, len);

    msg_node->len = len;
    msg_node->buf = msg_buf;
    msg_node->next = NULL;

    return msg_node;
}


int mbedtls_msg_node_append(t_msg_node_list *list,  t_msg_node *node)
{
    // to do : check if len overflow

    if (list->node_count == 0)
    {
        list->head = node;
        list->last = node;
    }
    else
    {
        //update last
        list->last->next = node;
        list->last = node;

    }
    list->node_count ++;
    list->node_msg_total_len +=  node->len;

#if 0
    printf("node_count:%d total_len:%d, node_len:%d, node last:%p, node next :%p\n",
           list->node_count, list->node_msg_total_len,
           list->last->len,
           list->last, node->next);
#endif
    return 0;

}

#define RESET_MSG_LIST(list) \
    { \
        list->head = NULL; \
        list->last = NULL; \
        list->node_count = 0; \
        list->node_msg_total_len = 0; \
    }



#define MOVE_TO_NEXT(cur, next) \
    { \
        cur = next; \
        next = cur->next; \
    }

int mbedtls_msg_node_lst_free(t_msg_node_list *list)
{
    uint32_t i = 0;
    t_msg_node *cur = NULL;
    t_msg_node *next = NULL;

    if (list->node_count == 0)
    {
        if ( (list->head != NULL) || (list->last != NULL) )
        {
            PUFS_LOG_ERR("count = 0 but head or last not null");
            return 1;
        }
    }
    else
    {
        cur = list->head;

        while (cur != NULL)
        {
            //Backup next before free.
            next = cur->next;

            if (cur->buf != NULL)
            {
                mbedtls_free(cur->buf);
                cur->buf = NULL;
            }
            else
            {
                PUFS_LOG_WARN("current buf is null ");
            }

            mbedtls_free(cur);

            cur = next;
            i++;

        }

        if (i != list->node_count)
        {
            PUFS_LOG_WARN("release count (%d) != list count (%d)", i, list->node_count);
        }
    }

#if 1
    RESET_MSG_LIST(list);
#else
    list->head = 0;
    list->last = 0;
    list->node_count = 0;
    list->node_msg_total_len = 0;
#endif
}

int mbedtls_sha256_update_checksum_msg_ret(mbedtls_sha256_context *ctx,
                                           const unsigned char *input,
                                           size_t ilen )
{

    t_msg_node *cur_node = NULL;
    t_msg_node_list *list = &(ctx->tls_msg_list);

#if (DEMO_LOG_LEVEL == 0 )
#else
    PUFS_LOG_FUNC("mbedtls_sha256_update_checksum_msg_ret\n");
#endif


    if ((input == NULL) || (ilen == 0))
    {
        PUFS_LOG_ERR("Incorrect parameter (null pointer (%p) or ilen(%d))",
                     (void *)input, ilen);
        return MBEDTLS_ERR_SHA256_BAD_INPUT_DATA;
    }

    cur_node = mbedtls_msg_node_alloc(ilen, input);

    if (cur_node == NULL)
    {
        PUFS_LOG_ERR("Allocate node failed!!");
        return 1;
    }

    mbedtls_msg_node_append( list, cur_node);

}


int mbedtls_sha256_update_checksum_ret( mbedtls_sha256_context *dst,
                                        const mbedtls_sha256_context *src )
{

    t_msg_node *cur_node = NULL;
    t_msg_node_list *list = &(src->tls_msg_list);
    int ret = 0;
    int i = 0;
    uint32_t update_size = 0;

    cur_node = list->head;

    PUFS_LOG_SHA_FUNC("mbedtls_sha256_update_checksum_ret\n");

    do
    {
        ret = pufs_mbedtls_sha256_update_ret(dst, cur_node->buf, cur_node->len);

        if (ret != 0)
        {
            PUFS_LOG_ERR("pufs_mbedtls_sha256_update_ret failed at node %d len:%d!!", i, cur_node->len);
            return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        }

        update_size += cur_node->len;
        cur_node = cur_node->next;
        i++;

    } while (cur_node != NULL);

    if ((i != list->node_count) || (update_size != list->node_msg_total_len))
    {
        PUFS_LOG_WARN("Mismatch list count or size !!! node/size : got %d/%d, expected %d/%d ",
                      i, update_size, list->node_count, list->node_msg_total_len);
    }

    return 0;
}


#endif /* 1 //MBEDTLS_PUFS_TLS_PRF_CALC_ALT */

#endif /* MBEDTLS_SHA256_ALT */



#endif /* MBEDTLS_SHA256_C */
