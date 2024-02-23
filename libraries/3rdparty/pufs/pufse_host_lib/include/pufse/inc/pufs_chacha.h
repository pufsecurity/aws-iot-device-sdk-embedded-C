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
 * @file      pufs_chacha.h
 * @brief     PUFsecurity ChaCha API interface
 * @copyright 2023 PUFsecurity
 */
#ifndef __PUFS_CHACHA_H__
#define __PUFS_CHACHA_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "pufs_basic.h"
#include "pufs_ka.h"

/**
 * @brief required parameters for chacha algorithm
 */
typedef struct chacha_params {
    pufs_key_type_t keytype; ///< Key type
    /** @note \em keyaddr may be a \ref pufs_rt_slot_t element, a \ref pufs_ka_slot_t
     *            element, or a memory address according to the \em keytype setting.
     *  @warning Set \ref PUFKEY or \ref SHARESEC as \em keytype is not allowed.
     */
    size_t          keyaddr;  ///< Key address
    uint32_t        keybits;  ///< Key length in bits
    const uint8_t  *iv;       ///< Initial vector
    uint32_t        ivlen;    ///< Initial vector length in bytes
    uint32_t        counter;  ///< Initial block counter
    // @note the default value of round is 20
    uint32_t        round;    ///< Initial quarter rounds
} pufs_chacha_params_st;

/**
 * @brief required parameters for chacha20-poly1305 algorithm
 */
typedef struct chacha20_poly1305_params {
    pufs_key_type_t keytype;  ///< Key type
    /** @note \em keyaddr may be a \ref pufs_rt_slot_t element, a \ref pufs_ka_slot_t
     *            element, or a memory address according to the \em keytype setting.
     *  @warning Set \ref PUFKEY or \ref SHARESEC as \em keytype is not allowed.
     */
    size_t          keyaddr;  ///< Key address
    uint32_t        keybits;  ///< Key length in bits
    const uint8_t  *iv;       ///< Initial vector
    uint32_t        ivlen;    ///< Initial vector length in bytes
} pufs_chacha20_poly1305_params_st;

/*****************************************************************************
 * Type definitions
 ****************************************************************************/
typedef struct pufs_chacha_context pufs_chacha_ctx;
typedef struct pufs_poly_context pufs_poly1305_ctx;
/*****************************************************************************
 * API functions
 ****************************************************************************/
/**
 * @brief Obtain a pointer to ChaCha internal context
 *
 * @return A pointer to ChaCha internal context, or NULL if error
 */
pufs_chacha_ctx *pufs_chacha_ctx_new(void);
/**
 * @brief Free a pointer to ChaCha internal context
 *
 * @param[in] chacha_ctx  A pointer to ChaCha context.
 */
void pufs_chacha_ctx_free(pufs_chacha_ctx *chacha_ctx);
/**
 * @brief Initialize ChaCha encryptor
 *
 * @param[in] chacha_ctx  ChaCha context to be initialized.
 * @param[in] params      Parameters for ChaCha algorithm.
 * @return                SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_chacha_enc_init(pufs_chacha_ctx *chacha_ctx,
                                   pufs_chacha_params_st *params);
/**
 * @brief Input data into ChaCha encryptor
 *
 * @param[in]  chacha_ctx  ChaCha context.
 * @param[out] out         Output data.
 * @param[out] outlen      Output data length in bytes.
 * @param[in]  in          Input data.
 * @param[in]  inlen       Input data length in bytes.
 * @return                 SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_chacha_enc_update(pufs_chacha_ctx *chacha_ctx,
                                     uint8_t *out,
                                     uint32_t *outlen,
                                     const uint8_t *in,
                                     uint32_t inlen);
/**
 * @brief Finalize ChaCha encryptor
 *
 * @param[in]  chacha_ctx ChaCha context.
 * @param[out] out        Output data. (set to NULL if using SGDMA descriptor)
 * @param[out] outlen     Output data length in bytes. (set to 0 if using SGDMA descriptor)
 * @return                SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_chacha_enc_final(pufs_chacha_ctx *chacha_ctx,
                                    uint8_t *out,
                                    uint32_t *outlen);
/**
 * @brief Encryption using ChaCha algorithm.
 *
 * @param[out] out      Output data.
 * @param[out] outlen   Output data length in bytes.
 * @param[in]  params   Parameters for ChaCha algorithm.
 * @param[in]  in       Input data.
 * @param[in]  inlen    Input data length in bytes.
 * @return              SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_chacha_enc(uint8_t *out,
                              uint32_t *outlen,
                              pufs_chacha_params_st *params,
                              const uint8_t *in,
                              uint32_t inlen);
/**
 * @brief Initialize ChaCha decryptor
 *
 * @param[in] pufs_chacha_ctx  ChaCha context to be initialized.
 * @param[in] params           Parameters for ChaCha algorithm.
 * @return                     SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_chacha_dec_init(pufs_chacha_ctx *chacha_ctx,
                                   pufs_chacha_params_st *params);
/**
 * @brief Input data into ChaCha decryptor
 *
 * @param[in]  chacha_ctx ChaCha context.
 * @param[out] out        Output data.
 * @param[out] outlen     Output data length in bytes.
 * @param[in]  in         Input data.
 * @param[in]  inlen      Input data length in bytes.
 * @return                SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_chacha_dec_update(pufs_chacha_ctx *chacha_ctx,
                                     uint8_t *out,
                                     uint32_t *outlen,
                                     const uint8_t *in,
                                     uint32_t inlen);
/**
 * @brief Finalize ChaCha decryptor
 *
 * @param[in]  chacha_ctx ChaCha context.
 * @param[out] out        Output data. (set to NULL if using SGDMA descriptor)
 * @param[out] outlen     Output data length in bytes. (set to 0 if using SGDMA descriptor)
 * @return                SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_chacha_dec_final(pufs_chacha_ctx *chacha_ctx,
                                    uint8_t *out,
                                    uint32_t *outlen);
/**
 * @brief Decryption using ChaCha algorithm.
 *
 * @param[out] out      Output data.
 * @param[out] outlen   Output data length in bytes.
 * @param[in]  params   Parameters for ChaCha algorithm.
 * @param[in]  in       Input data.
 * @param[in]  inlen    Input data length in bytes.
 * @return              SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_chacha_dec(uint8_t *out,
                              uint32_t *outlen,
                              pufs_chacha_params_st *params,
                              const uint8_t *in,
                              uint32_t inlen);

/// Poly1305
/**
 * @brief Initialize ChaCha20-Poly1305 encryptor
 *
 * @param[in] chacha_ctx  ChaCha context to be initialized.
 * @param[in] params      Parameters for ChaCha20-Poly1305 algorithm.
 * @return                SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_chacha20_poly1305_enc_init(pufs_chacha_ctx *chacha_ctx,
                                              pufs_chacha20_poly1305_params_st *params);
/**
 * @brief Input data into ChaCha20-Poly1305 encryptor
 *
 * @param[in]  chacha_ctx  ChaCha context.
 * @param[out] out         Output data.
 * @param[out] outlen      Output data length in bytes.
 * @param[in]  in          Input data.
 * @param[in]  inlen       Input data length in bytes.
 * @return                 SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_chacha20_poly1305_enc_update(pufs_chacha_ctx *chacha_ctx,
                                                uint8_t *out,
                                                uint32_t *outlen,
                                                const uint8_t *in,
                                                uint32_t inlen);
/**
 * @brief Finalize ChaCha20-Poly1305 encryptor
 *
 * @param[in]  chacha_ctx ChaCha context.
 * @param[out] out        Output data. (set to NULL if using SGDMA descriptor)
 * @param[out] outlen     Output data length in bytes. (set to 0 if using SGDMA descriptor)
 * @param[out] tag        Output Tag.
 * @return                SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_chacha20_poly1305_enc_final(pufs_chacha_ctx *chacha_ctx,
                                               uint8_t *out,
                                               uint32_t *outlen,
                                               uint8_t *tag);
/**
 * @brief Encryption using ChaCha20-Poly1305 algorithm.
 *
 * @param[out] out      Output data.
 * @param[out] outlen   Output data length in bytes.
 * @param[out] tag      Output Tag.
 * @param[in]  params   Parameters for ChaCha20-Poly1305 algorithm.
 * @param[in]  aad      Additional authenticated data.
 * @param[in]  aadlen   The length of additional authenticated data.
 * @param[in]  in       Input data.
 * @param[in]  inlen    Input data length in bytes.
 * @return              SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_chacha20_poly1305_enc(uint8_t *out,
                                         uint32_t *outlen,
                                         uint8_t *tag,
                                         pufs_chacha20_poly1305_params_st *params,
                                         const uint8_t *aad,
                                         uint32_t aadlen,
                                         const uint8_t *in,
                                         uint32_t inlen);
/**
 * @brief Initialize ChaCha20-Poly1305 decryptor
 *
 * @param[in] pufs_chacha_ctx  ChaCha context to be initialized.
 * @param[in] params           Parameters for ChaCha20-Poly1305 algorithm.
 * @return                     SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_chacha20_poly1305_dec_init(pufs_chacha_ctx *chacha_ctx,
                                              pufs_chacha20_poly1305_params_st *params);
/**
 * @brief Input data into ChaCha20-Poly1305 decryptor
 *
 * @param[in]  chacha_ctx ChaCha context.
 * @param[out] out        Output data.
 * @param[out] outlen     Output data length in bytes.
 * @param[in]  in         Input data.
 * @param[in]  inlen      Input data length in bytes.
 * @return                SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_chacha20_poly1305_dec_update(pufs_chacha_ctx *chacha_ctx,
                                                uint8_t *out,
                                                uint32_t *outlen,
                                                const uint8_t *in,
                                                uint32_t inlen);

/**
 * @brief Finalize ChaCha20-Poly1305 decryptor
 *
 * @param[in]  chacha_ctx ChaCha context.
 * @param[out] out        Output data. (set to NULL if using SGDMA descriptor)
 * @param[out] outlen     Output data length in bytes. (set to 0 if using SGDMA descriptor)
 * @param[in]  tag        Input tag.
 * @return                SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_chacha20_poly1305_dec_final(pufs_chacha_ctx *chacha_ctx,
                                               uint8_t *out,
                                               uint32_t *outlen,
                                               uint8_t *tag);
/**
 * @brief Decryption using ChaCha20-Poly1305 algorithm.
 *
 * @param[out] out      Output data.
 * @param[out] outlen   Output data length in bytes.
 * @param[in]  params   Parameters for ChaCha20-Poly1305 algorithm.
 * @param[in]  aad      Additional authenticated data.
 * @param[in]  aadlen   The length of additional authenticated data.
 * @param[in]  in       Input data.
 * @param[in]  inlen    Input data length in bytes.
 * @param[in]  tag      Input tag.
 * @return              SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_chacha20_poly1305_dec(uint8_t *out,
                                         uint32_t *outlen,
                                         pufs_chacha20_poly1305_params_st *params,
                                         const uint8_t *aad,
                                         uint32_t aadlen,
                                         const uint8_t *in,
                                         uint32_t inlen,
                                         uint8_t *tag);
#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /*__PUFS_CMD_CHACHA_H__*/
