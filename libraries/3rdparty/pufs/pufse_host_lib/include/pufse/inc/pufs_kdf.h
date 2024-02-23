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
 * @file      pufs_kdf.h
 * @brief     PUFsecurity KDF API interface
 * @copyright 2023 PUFsecurity
 */
#ifndef __PUFS_KDF_H__
#define __PUFS_KDF_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "pufs_basic.h"
#include "pufs_hmac.h"
/*****************************************************************************
 * Macros
 ****************************************************************************/
/*****************************************************************************
 * Enumerations
 ****************************************************************************/
/**
 * @brief Pseudo-random function family used by KDF
 */
typedef enum {
    PRF_HMAC,      ///< HMAC
    PRF_HASH,      ///< HASH
    PRF_CMAC,      ///< CMAC
    N_PRFFAMILY_T, // keep in the last one
} pufs_prf_family_t;
/*****************************************************************************
 * Macros
 ****************************************************************************/
/*****************************************************************************
 * Structures
 ****************************************************************************/
/*****************************************************************************
 * API functions
 ****************************************************************************/
/**
 * @brief Generate a session key from a KDK derived from a shared secret.
 *
 * @param[in] keytype   Derived key type.
 * @param[in] keyslot   Slot in KA to store derived key.
 * @param[in] outbits   Derived key length in bits.
 * @param[in] prf       Pseudo-random function (PRF) family.
 * @param[in] hash      Hash algorithm for PRF used in HKDF.
 * @param[in] feedback  True/false to enable/disable feedback mode.
 * @param[in] iv        Initial vector.
 * @param[in] ctrpos    The position of the counter inserted in the fixedinfo.
 * @param[in] ctrlen    The length of the inserted counter in bytes.
 * @param[in] ztype     Key type of shared secret Z.
 * @param[in] zaddr     Key slot of shared secret Z.
 * @param[in] zbits     Length of shared secret Z in bits.
 * @param[in] salt      Salt used by KDF to derive KDK.
 * @param[in] saltlen   Salt length in bytes.
 * @param[in] info      Fixed info used by KDF key expansion.
 * @param[in] infolen   Fixed info length in bytes.
 * @return              SUCCESS on success, otherwise an error code.
 *
 * @note Only \ref SSKEY and \ref SHARESEC are allowed \em keytype.
 * @note \em iv is used in feedback mode. The length equals to the output of the
 *       underlying \em hash. It can be set to NULL if iv is not used in
 *       feedback mode.
 * @note Without feedback, \em ctrpos is in range [0, max(infolen,255)]. 0 or
 *       infolen means the counter is prepended or appended to the fixed info.
 *       In feedback mode, \em ctrpos is set to one of 0, 1, or 2 indicating the
 *       counter is before the feedback value, adter the feedback value, or
 *       after the fixed info.
 * @note \em ctrlen is in range [1, 4] in general. In feedback mode, \em ctrlen
 *       can be set to 0 indicating counter is not used.
 * @note \em zaddr may be a \ref pufs_rt_slot_t element, a \ref pufs_ka_slot_t
 *       element, or a memory address according to the \em ztype setting.
 */
#define pufs_kdf(keytype, keyslot, outbits, prf, hash, feedback, iv, ctrpos, ctrlen, ztype, zaddr, zbits, salt, saltlen, info, infolen)\
    _pufs_kdf(keytype, keyslot, outbits, prf, hash, feedback, iv, ctrpos, ctrlen,\
              ztype, (size_t)zaddr, zbits, salt, saltlen, info, infolen)
/**
 * @brief KDF function with zaddr type casting
 *
 * @warning DO NOT call this function directly. Use pufs_kdf() instead.
 */
pufs_status_t _pufs_kdf(pufs_key_type_t keytype,
                        pufs_ka_slot_t keyslot,
                        uint32_t outbits,
                        pufs_prf_family_t prf,
                        pufs_hash_t hash,
                        bool feedback,
                        const uint8_t *iv,
                        uint32_t ctrpos,
                        uint32_t ctrlen,
                        pufs_key_type_t ztype,
                        size_t zaddr,
                        uint32_t zbits,
                        const uint8_t *salt,
                        uint32_t saltlen,
                        const uint8_t *info,
                        uint32_t infolen);
/**
 * @brief Derive a session key from a KDK.
 *
 * @param[in] keytype   Derived key type.
 * @param[in] keyslot   Slot in KA to store derived key.
 * @param[in] outbits   Derived key length in bits.
 * @param[in] prf       Pseudo-random function (PRF) family.
 * @param[in] hash      Hash algorithm for HMAC used in HKDF.
 * @param[in] feedback  True/false to enable/disable feedback mode.
 * @param[in] iv        Initial vector.
 * @param[in] ctrpos    The position of the counter inserted in the fixedinfo.
 * @param[in] ctrlen    The length of the inserted counter in bytes.
 * @param[in] kdktype   KDK key type.
 * @param[in] kdkaddr   KDK key address.
 * @param[in] kdkbits   Length of KDK key in bits.
 * @param[in] info      Fixed info used by KDF key expansion.
 * @param[in] infolen   Fixed info length in bytes.
 * @return              SUCCESS on success, otherwise an error code.
 *
 * @note Only \ref SSKEY and \ref SHARESEC are allowed \em keytype.
 * @note \em iv is used in feedback mode. The length equals to the output of the
 *       underlying \em hash. It can be set to NULL if iv is not used in
 *       feedback mode.
 * @note Without feedback, \em ctrpos is in range [0, max(infolen,255)]. 0 or
 *       infolen means the counter is prepended or appended to the fixed info.
 *       In feedback mode, \em ctrpos is set to one of 0, 1, or 2 indicating the
 *       counter is before the feedback value, adter the feedback value, or
 *       after the fixed info.
 * @note \em ctrlen is in range [1, 4] in general. In feedback mode, \em ctrlen
 *       can be set to 0 indicating counter is not used.
 * @note \em kdkaddr may be a \ref pufs_rt_slot_t element, a \ref pufs_ka_slot_t
 *       element, or a memory address according to the \em kdktype setting.
 */
#define pufs_key_expansion(keytype, keyslot, outbits, prf, hash, feedback, iv, ctrpos, ctrlen, kdktype, kdkaddr, kdkbits, info, infolen)\
    _pufs_key_expansion(keytype, keyslot, outbits, prf, hash, feedback, iv, ctrpos, ctrlen,\
                        kdktype, (size_t)kdkaddr, kdkbits, info, infolen)
/**
 * @brief Key expansion function with kdkaddr type casting
 *
 * @warning DO NOT call this function directly. Use pufs_key_expansion()
 *          instead.
 */
pufs_status_t _pufs_key_expansion(pufs_key_type_t keytype,
                                  pufs_ka_slot_t keyslot,
                                  uint32_t outbits,
                                  pufs_prf_family_t prf,
                                  pufs_hash_t hash,
                                  bool feedback,
                                  const uint8_t *iv,
                                  uint32_t ctrpos,
                                  uint32_t ctrlen,
                                  pufs_key_type_t kdktype,
                                  size_t kdkaddr,
                                  uint32_t kdkbits,
                                  const uint8_t *info,
                                  uint32_t infolen);
/**
 * @brief Derive a session key by PBKDF.
 *
 * @param[in] keytype   Derived key type.
 * @param[in] keyslot   Slot in KA to store derived key.
 * @param[in] outbits   Derived key length in bits.
 * @param[in] prf       Pseudo-random function (PRF) family.
 * @param[in] hash      Hash algorithm for HMAC used in HKDF.
 * @param[in] iter      The number of iterations desired.
 * @param[in] salttype  PBKDF salt type.
 * @param[in] saltaddr  PBKDF salt address.
 * @param[in] saltbits  Length of PBKDF salt in bits.
 * @param[in] pass      PBKDF password.
 * @param[in] passlen   PBKDF password length in bytes.
 * @return              SUCCESS on success, otherwise an error code.
 *
 * @note Only \ref SSKEY and \ref SHARESEC are allowed \em keytype.
 * @note \em saltaddr may be a \ref pufs_rt_slot_t element, a \ref
 *       pufs_ka_slot_t element, or a memory address according to the
 *       \em salttype setting.
 */
#define pufs_pbkdf(keytype, keyslot, outbits, prf, hash, iter, salttype, saltaddr, saltbits, pass, passlen) \
    _pufs_pbkdf(keytype, keyslot, outbits, prf, hash, iter, salttype, (size_t)saltaddr, saltbits, pass, passlen)
/**
 * @brief PBKDF function with saltaddr type casting
 *
 * @warning DO NOT call this function directly. Use pufs_pbkdf()
 *          instead.
 */
pufs_status_t _pufs_pbkdf(pufs_key_type_t keytype,
                          pufs_ka_slot_t keyslot,
                          uint32_t outbits,
                          pufs_prf_family_t prf,
                          pufs_hash_t hash,
                          uint32_t iter,
                          pufs_key_type_t salttype,
                          size_t saltaddr,
                          uint32_t saltbits,
                          const uint8_t *pass,
                          uint32_t passlen);
#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /*__PUFS_KDF_H__*/
