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
 * @file      pufs_drbg.h
 * @brief     PUFsecurity DRBG API interface
 * @copyright 2023 PUFsecurity
 */
#ifndef __PUFS_DRBG_H__
#define __PUFS_DRBG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "pufs_basic.h"
/*****************************************************************************
 * Enumerations
 ****************************************************************************/
/**
 * @brief DRBG underlying cryptographic primitives
 */
typedef enum {
    AES_CTR_DRBG,  ///< DRBG mechanisms based on AES-CTR mode
    HASH_DRBG,     ///< DRBG mechanisms based on Hash functions
    HMAC_DRBG,     ///< DRBG mechanisms based on HMAC functions
} pufs_drbg_t;

/*****************************************************************************
 * API functions
 ****************************************************************************/
/**
 * @brief Instantiate DRBG
 *
 * @param[in] mode      DRBG underlying cryptographic primitive
 * @param[in] security  Required security strength in bits.
 * @param[in] df        Use derivation functi on or not.
 * @param[in] nonce     Nonce.
 * @param[in] noncelen  Length of nonce in bytes.
 * @param[in] pstr      Personalization string.
 * @param[in] pstrlen   Length of personalization string in bytes.
 * @return              SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_drbg_instantiate(pufs_drbg_t mode,
                                    uint32_t security,
                                    bool df,
                                    const uint8_t *nonce,
                                    uint32_t noncelen,
                                    const uint8_t *pstr,
                                    uint32_t pstrlen);
/**
 * @brief Reseed DRBG
 *
 * @param[in] df       Use derivation function or not.
 * @param[in] adin     Additional input.
 * @param[in] adinlen  Length of additional input in bytes.
 * @return             SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_drbg_reseed(bool df, const uint8_t *adin, uint32_t adinlen);
/**
 * @brief Generate random bits from DRBG
 *
 * @param[out] out       Random bits.
 * @param[in]  outbits   Length of output in bits.
 * @param[in]  pr        Prediction resistance request.
 * @param[in]  df        Use derivation function or not.
 * @param[in]  adin      Additional input.
 * @param[in]  adinlen   Length of additional input in bytes.
 * @param[in]  testmode  In test mode or not.
 * @return               SUCCESS on success, otherwise an error code.
 *
 * @note error reported if \em testmode is false but DRBG test mode is enabled.
 */
pufs_status_t pufs_drbg_generate(uint8_t *out,
                                 uint32_t outbits,
                                 bool pr,
                                 bool df,
                                 const uint8_t *adin,
                                 uint32_t adinlen,
                                 uint32_t testmode);
/**
 * @brief Uninstantiate DRBG
 *
 * @return  SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_drbg_uninstantiate(void);

#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /*__PUFS_DRBG_H__*/
