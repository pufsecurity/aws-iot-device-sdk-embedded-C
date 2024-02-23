/*
 * Copyright (c) 2023 PUFsecurity. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS SUPPLIED BY PUFSECURITY ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. TO THE FULLEST
 * EXTENT ALLOWED BY LAW, PUFSECURITY'S TOTAL LIABILITY ON ALL CLAIMS IN
 * ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES,
 * IF ANY, THAT YOU HAVE PAID DIRECTLY TO PUFSECURITY FOR THIS SOFTWARE.
 */
/**
 * @file      pufs_cmd_hmac.h
 * @brief     PUFsecurity HMAC API interface
 * @copyright 2023 PUFsecurity
 */
#ifndef __PUFS_HMAC_H__
#define __PUFS_HMAC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "pufs_basic.h"
#include "pufs_ka.h"
/*****************************************************************************
 * Type definitions
 ****************************************************************************/
typedef struct pufs_hmac_context pufs_hmac_ctx;
typedef pufs_hmac_ctx pufs_hash_ctx;

/*****************************************************************************
 * Enumerations
 ****************************************************************************/
/**
 * @brief Cryptographic hash algorithms
 */
typedef enum {
    PUFSE_MD5,                    ///< MD5
    PUFSE_SHA1,                   ///< SHA1
    PUFSE_SHA_224,                ///< SHA2-224
    PUFSE_SHA_256,                ///< SHA2-256
    HASH_DEFAULT = PUFSE_SHA_256, ///< Default to SHA2-256
    PUFSE_SHA_384,                ///< SHA2-384
    PUFSE_SHA_512,                ///< SHA2-512
    PUFSE_SHA_512_224,            ///< SHA2-512/224
    PUFSE_SHA_512_256,            ///< SHA2-512/256
    PUFSE_SM3,                    ///< SM3
    PUFSE_SHA3_224,               ///< SHA3-224
    PUFSE_SHA3_256,               ///< SHA3-256
    PUFSE_SHA3_384,               ///< SHA3-384
    PUFSE_SHA3_512,               ///< SHA3-512
    PUFSE_SHAKE_128,              ///< SHAKE-128
    PUFSE_SHAKE_256,              ///< SHAKE-256
    N_HASH_T,               // keep in the last one
} pufs_hash_t;
/*****************************************************************************
 * API functions
 ****************************************************************************/
/**
 * @brief Obtain a pointer to HMAC internal context
 *
 * @return A pointer to HMAC internal context, or NULL if error
 */
pufs_hmac_ctx *pufs_hmac_ctx_new(void);
#define pufs_hash_ctx_new() pufs_hmac_ctx_new()
/**
 * @brief Free a pointer to HMAC internal context
 *
 * @param[in] hmac_ctx  A pointer to HMAC context.
 */
void pufs_hmac_ctx_free(pufs_hmac_ctx *hmac_ctx);
#define pufs_hash_ctx_free(hmac_ctx) pufs_hmac_ctx_free(hmac_ctx)

/**
 * @brief Initialize hash calculator
 *
 * @param[in] hmac_ctx  HMAC context.
 * @param[in] hash      Hash algorithm.
 * @return              SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_hash_init(pufs_hash_ctx *hash_ctx, pufs_hash_t hash);
/**
 * @brief Input data into hash calculator
 *
 * @param[in] hmac_ctx  HMAC context.
 * @param[in] msg       Message.
 * @param[in] msglen    Message length in bytes.
 * @return              SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_hash_update(pufs_hash_ctx *hash_ctx,
                               const uint8_t *msg,
                               uint32_t msglen);
/**
 * @brief Extract message digest from hash calculator
 *
 * @param[in]  hmac_ctx  HMAC context.
 * @param[out] md        Message digest.
 * @return               SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_hash_final(pufs_hash_ctx *hash_ctx, pufs_dgst_st *md);
/**
 * @brief Calculate hash value of a message.
 *
 * @param[out] md      Message digest.
 * @param[in]  msg     Message.
 * @param[in]  msglen  Message length in bytes.
 * @param[in]  hash    Hash algorithm.
 * @return             SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_hash(pufs_dgst_st *md,
                        const uint8_t *msg,
                        uint32_t msglen,
                        pufs_hash_t hash);
/**
 * @brief Initialize HMAC calculator
 *
 * @param[in] hmac_ctx  HMAC context.
 * @param[in] hash      Hash algorithm.
 * @param[in] keytype   Key type.
 * @param[in] keyaddr   Key address.
 * @param[in] keybits   Key length in bits.
 * @return              SUCCESS on success, otherwise an error code.
 *
 * @note \em keyaddr may be a \ref pufs_rt_slot_t element, a \ref pufs_ka_slot_t
 *       element, or a memory address according to the \em keytype setting.
 * @warning Set \ref PUFKEY or \ref SHARESEC as \em keytype is not allowed.
 */
#define pufs_hmac_init(hmac_ctx, hash, keytype, keyaddr, keybits) \
    _pufs_hmac_init(hmac_ctx, hash, keytype, (size_t)keyaddr, keybits)
/**
 * @brief HMAC calculator initializer with keyaddr type casting
 *
 * @warning DO NOT call this function directly. Use pufs_hmac_init() instead.
 */
pufs_status_t _pufs_hmac_init(pufs_hmac_ctx *hmac_ctx,
                              pufs_hash_t hash,
                              pufs_key_type_t keytype,
                              size_t keyaddr,
                              uint32_t keybits);
/**
 * @brief Input data into HMAC calculator
 *
 * @param[in] hmac_ctx  HMAC context.
 * @param[in] msg     Message.
 * @param[in] msglen  Message length in bytes.
 * @return            SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_hmac_update(pufs_hmac_ctx *hmac_ctx,
                               const uint8_t *msg,
                               uint32_t msglen);
/**
 * @brief Extract message digest from HMAC calculator
 *
 * @param[in]  hmac_ctx  HMAC context.
 * @param[out] md        Message digest.
 * @return               SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_hmac_final(pufs_hmac_ctx *hmac_ctx, pufs_dgst_st *md);
/**
 * @brief Calculate HMAC hash value of a message with a key.
 *
 * @param[out] md       Message digest.
 * @param[in]  msg      Message.
 * @param[in]  msglen   Message length in bytes.
 * @param[in]  hash     Hash algorithm.
 * @param[in]  keytype  Key type.
 * @param[in]  keyaddr  Key address.
 * @param[in]  keybits  Key length in bits.
 * @return              SUCCESS on success, otherwise an error code.
 *
 * @note \em keyaddr may be a \ref pufs_rt_slot_t element, a \ref pufs_ka_slot_t
 *       element, or a memory address according to the \em keytype setting.
 * @warning Set \ref PUFKEY or \ref SHARESEC as \em keytype is not allowed.
 */
#define pufs_hmac(md, msg, msglen, hash, keytype, keyaddr, keybits)\
    _pufs_hmac(md, msg, msglen, hash, keytype, (size_t)keyaddr, keybits)
/**
 * @brief HMAC calculator with keyaddr type casting
 *
 * @warning DO NOT call this function directly. Use pufs_hmac() instead.
 */
pufs_status_t _pufs_hmac(pufs_dgst_st *md,
                         const uint8_t *msg,
                         uint32_t msglen,
                         pufs_hash_t hash,
                         pufs_key_type_t keytype,
                         size_t keyaddr,
                         uint32_t keybits);
#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /*__PUFS_HMAC_H__*/
