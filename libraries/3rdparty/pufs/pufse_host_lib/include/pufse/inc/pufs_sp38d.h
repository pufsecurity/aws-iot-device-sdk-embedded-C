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
 * @file      pufs_sp38d.h
 * @brief     PUFsecurity sp38d API interface
 * @copyright 2023 PUFsecurity
 */
#ifndef __PUFS_SP38D_H__
#define __PUFS_SP38D_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "pufs_basic.h"
#include "pufs_ka.h"
/*****************************************************************************
 * Type definitions
 ****************************************************************************/
typedef struct pufs_sp38d_context pufs_sp38d_ctx;

/*****************************************************************************
 * API functions
 ****************************************************************************/
/**
 * @brief Obtain a pointer to SP38D internal context
 *
 * @return A pointer to SP38D internal context, or NULL if error
 */
pufs_sp38d_ctx *pufs_sp38d_ctx_new(void);
/**
 * @brief Free a pointer to SP38D internal context
 *
 * @param[in] sp38d_ctx  A pointer to SP38D context.
 */
void pufs_sp38d_ctx_free(pufs_sp38d_ctx *sp38d_ctx);
/**
 * @brief Initialize GCM encryptor
 *
 * @param[in] sp38d_ctx  SP38D context to be initialized.
 * @param[in] cipher     Block cipher algorithm.
 * @param[in] keytype    Key type.
 * @param[in] keyaddr    Key address.
 * @param[in] keybits    Key length in bits.
 * @param[in] iv         Initial vector.
 * @param[in] ivlen      Initial vector length in bytes.
 * @return               SUCCESS on success, otherwise an error code.
 *
 * @note \em keyaddr may be a \ref pufs_rt_slot_t element, a \ref pufs_ka_slot_t
 *       element, or a memory address according to the \em keytype setting.
 * @warning Set \ref PUFKEY or \ref SHARESEC as \em keytype is not allowed.
 */
#define pufs_enc_gcm_init(sp38d_ctx, cipher, keytype, keyaddr, keybits, iv, ivlen)\
    _pufs_enc_gcm_init(sp38d_ctx, cipher, keytype, (size_t)keyaddr, keybits, iv, ivlen)
/**
 * @brief GCM encryptor initializer with keyaddr type casting
 *
 * @warning DO NOT call this function directly. Use pufs_enc_gcm_init() instead.
 */
pufs_status_t _pufs_enc_gcm_init(pufs_sp38d_ctx *sp38d_ctx,
                                 pufs_cipher_t cipher,
                                 pufs_key_type_t keytype,
                                 size_t keyaddr,
                                 uint32_t keybits,
                                 const uint8_t *iv,
                                 uint32_t ivlen);
/**
 * @brief Input data into GCM encryptor
 *
 * @param[in]  sp38d_ctx  SP38D context.
 * @param[out] out        Output data.
 * @param[out] outlen     Output data length in bytes.
 * @param[in]  in         Input data.
 * @param[in]  inlen      Input data length in bytes.
 * @return                SUCCESS on success, otherwise an error code.
 *
 * @note Input data may be either AAD or plaintext. Set \a out to NULL when
 *       input AAD. Complete AAD data must be passed first before the plaintext.
 */
pufs_status_t pufs_enc_gcm_update(pufs_sp38d_ctx *sp38d_ctx,
                                  uint8_t *out,
                                  uint32_t *outlen,
                                  const uint8_t *in,
                                  uint32_t inlen);
/**
 * @brief Finalize GCM encryptor
 *
 * @param[in]  sp38d_ctx  SP38D context.
 * @param[out] out        Output data.
 * @param[out] outlen     Output data length in bytes.
 * @param[out] tag        Output tag.
 * @param[in]  taglen     Specified output tag length in bytes.
 * @return                SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_enc_gcm_final(pufs_sp38d_ctx *sp38d_ctx,
                                 uint8_t *out,
                                 uint32_t *outlen,
                                 uint8_t *tag,
                                 uint32_t taglen);
/**
 * @brief Initialize GCM decryptor
 *
 * @param[in] sp38d_ctx  SP38D context to be initialized.
 * @param[in] cipher     Block cipher algorithm.
 * @param[in] keytype    Key type.
 * @param[in] keyaddr    Key address.
 * @param[in] keybits    Key length in bits.
 * @param[in] iv         Initial vector.
 * @param[in] ivlen      Initial vector length in bytes.
 * @return               SUCCESS on success, otherwise an error code.
 *
 * @note \em keyaddr may be a \ref pufs_rt_slot_t element, a \ref pufs_ka_slot_t
 *       element, or a memory address according to the \em keytype setting.
 * @warning Set \ref PUFKEY or \ref SHARESEC as \em keytype is not allowed.
 */
#define pufs_dec_gcm_init(sp38d_ctx, cipher, keytype, keyaddr, keybits, iv, ivlen)\
    _pufs_dec_gcm_init(sp38d_ctx, cipher, keytype, (size_t)keyaddr, keybits, iv, ivlen)
/**
 * @brief GCM decryptor initializer with keyaddr type casting
 *
 * @warning DO NOT call this function directly. Use pufs_dec_gcm_init() instead.
 */
pufs_status_t _pufs_dec_gcm_init(pufs_sp38d_ctx *sp38d_ctx,
                                 pufs_cipher_t cipher,
                                 pufs_key_type_t keytype,
                                 size_t keyaddr,
                                 uint32_t keybits,
                                 const uint8_t *iv,
                                 uint32_t ivlen);
/**
 * @brief Input data into GCM decryptor
 *
 * @param[in]  sp38d_ctx  SP38D context.
 * @param[out] out        Output data.
 * @param[out] outlen     Output data length in bytes.
 * @param[in]  in         Input data.
 * @param[in]  inlen      Input data length in bytes.
 * @return                SUCCESS on success, otherwise an error code.
 *
 * @note Input data may be either AAD or plaintext. Set \a out to NULL when
 *       input AAD. Complete AAD data must be passed first before the plaintext.
 */
pufs_status_t pufs_dec_gcm_update(pufs_sp38d_ctx *sp38d_ctx,
                                  uint8_t *out,
                                  uint32_t *outlen,
                                  const uint8_t *in,
                                  uint32_t inlen);
/**
 * @brief Finalize GCM decryptor
 *
 * @param[in]  sp38d_ctx  SP38D context.
 * @param[out] out        Output data.
 * @param[out] outlen     Output data length in bytes.
 * @param[in]  tag        Input tag.
 * @param[in]  taglen     Specified input tag length in bytes.
 * @return                SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_dec_gcm_final(pufs_sp38d_ctx *sp38d_ctx,
                                 uint8_t *out,
                                 uint32_t *outlen,
                                 uint8_t *tag,
                                 uint32_t taglen);
#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /*__PUFS_SP38D_H__*/
