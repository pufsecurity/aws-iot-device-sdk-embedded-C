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
#include "pufs_cmd_hmac.h"

#ifdef __cplusplus
extern "C" {
#endif

extern uint8_t g_sha_log;

typedef struct msg_node
{
    struct msg_node *next;
    uint8_t *buf;
    uint32_t len;
} t_msg_node;


typedef struct msg_node_list
{
    t_msg_node *head;
    t_msg_node *last;
    uint32_t node_count;
    uint32_t node_msg_total_len;
} t_msg_node_list;


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
    t_msg_node_list tls_msg_list;          /*msg list for tls cal verify */

} mbedtls_sha256_context;



// MBEDTLS_PUFS_TLS_PRF_CALC_ALT +++
/**
 * \brief          This function alloc a node to store the input buffer data
 *                 and then add the node to msg_node_list for
 *                 SHA-256 checksum calculation of tls handshacking verify functions.
 *
 * \param ctx      The SHA-256 context. This must be initialized
 *                 and have a hash operation started.
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */

int mbedtls_sha256_update_checksum_msg_ret(mbedtls_sha256_context *ctx,
                                           const unsigned char *input,
                                           size_t ilen );


/**
 * \brief          This function calculates the SHA-256 checksum of all node data
 *                 currently in the msg_node_list of src context.
 *                 The outpuf and states will be stored in the dst context
 *
 * \param dst      The destination context. This must be initialized.
 * \param src      The context to clone. This must be initialized.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sha256_update_checksum_ret( mbedtls_sha256_context *dst,
                                        const mbedtls_sha256_context *src );


//MBEDTLS_PUFS_TLS_PRF_CALC_ALT ---

#define PUFS_LOG_SHA_FUNC(...)        \
  {                                   \
      if (g_sha_log > 0 )             \
      {                               \
          PRINT("      ");   \
          PRINT("%s",  ## __VA_ARGS__);   \
      }                               \
  }

#if defined(PUFSE_HOST) && defined(MBEDTLS_SHA256_ALT)
#define PUFS_SHA_FUNC_LOG_ON \
   {                         \
       g_sha_log = 1;        \
   }

#define PUFS_SHA_FUNC_LOG_OFF \
   {                          \
       g_sha_log = 0;         \
   }

#endif

#ifdef __cplusplus
}
#endif

#endif /* SHA256_ALT_H */
