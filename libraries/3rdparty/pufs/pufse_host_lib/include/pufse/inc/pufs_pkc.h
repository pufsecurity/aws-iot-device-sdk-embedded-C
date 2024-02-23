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
 * @file      pufs_pkc.h
 * @brief     PUFsecurity pkc API interface
 * @copyright 2023 PUFsecurity
 */
#ifndef __PUFS_PKC_H__
#define __PUFS_PKC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "pufs_basic.h"
#include "pufs_hmac.h"
#include "pufs_ka.h"
#include "pufs_rt.h"
/*****************************************************************************
 * Macros
 ****************************************************************************/
/**
 * @brief Maximum field element length in bytes.
 */
#ifndef QLEN_MAX
#define QLEN_MAX 72
#endif
/**
 * @brief Elliptic curve point (x,y).
 */
typedef struct {
    uint32_t qlen;       ///< Field element length in bytes.
    uint8_t x[QLEN_MAX]; ///< x-coordinate
    uint8_t y[QLEN_MAX]; ///< y-coordinate
} pufs_ec_point_st;
/**
 * @brief Maximum field element length in bytes.
 */
#ifndef NLEN_MAX
#define NLEN_MAX 72
#endif

/*****************************************************************************
 * Enumerations
 ****************************************************************************/
/**
 * @brief RSA variant.
 */
typedef enum {
    RSA1024,      ///< RSA-1024
    RSA2048,      ///< RSA-2048
    RSA3072,      ///< RSA-3072
    RSA4096,      ///< RSA-4096
    N_RSA_TYPE_T, // keep in the last one
} pufs_rsa_type_t;
/**
 * @brief NIST standardized elliptic curves.
 */
typedef enum {
    NISTB163,   ///< NIST B-163
    NISTB233,   ///< NIST B-233
    NISTB283,   ///< NIST B-283
    NISTB409,   ///< NIST B-409
    NISTB571,   ///< NIST B-571
    NISTK163,   ///< NIST K-163
    NISTK233,   ///< NIST K-233
    NISTK283,   ///< NIST K-283
    NISTK409,   ///< NIST K-409
    NISTK571,   ///< NIST K-571
    NISTP192,   ///< NIST P-192
    NISTP224,   ///< NIST P-224
    NISTP256,   ///< NIST P-256
    NISTP384,   ///< NIST P-384
    NISTP521,   ///< NIST P-521
    SM2,        ///< SM2
    N_ECNAME_T, // keep in the last one
} pufs_ec_name_t;
/*****************************************************************************
 * Macros
 ****************************************************************************/
/*****************************************************************************
 * Structures
 ****************************************************************************/
/**
 * @brief Elliptic curve (EC) domain parameters
 */
typedef struct {
    const void *field; ///< Field modulus.
    const void *a;     ///< EC parameter a.
    const void *b;     ///< EC parameter b.
    const void *px;    ///< x-coordinate of base point P.
    const void *py;    ///< y-coordinate of base point P.
    const void *order; ///< Subgroup order.
    uint16_t fbits;    ///< Field element length in bits.
    uint16_t nbits;    ///< Subgroup order length in bits.
    uint8_t ftype;     ///< Field type in hardware.
    uint8_t h;         ///< Co-factor.
    uint8_t len;       ///< Field element length in bytes.
    bool pf;           ///< Prime field flag
} pufs_ecc_param_st;
/**
 * @brief ECDSA signature (r,s).
 */
typedef struct {
    uint32_t qlen;       ///< Field element length in bytes.
    uint8_t r[NLEN_MAX]; ///< r
    uint8_t s[NLEN_MAX]; ///< s
} pufs_ecdsa_sig_st;
/*****************************************************************************
 * API functions
 ****************************************************************************/
/**
 * @brief Set elliptic curve domain parameters by name.
 *
 * @param[in] name  Elliptic curve name.
 * @return          SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_ecp_set_curve_byname(pufs_ec_name_t name);
/**
 * @brief Generate static ECC private key.
 *
 * @param[in] slot     Private key slot.
 * @param[in] pufslot  PUF slots (1-3).
 * @param[in] salt     Salt used by the KDF to derive KDK.
 * @param[in] saltlen  Salt length.
 * @param[in] info     Info used in KDF.
 * @param[in] infolen  Info length.
 * @param[in] hash     Hash algorithm. Default is SHA256.
 * @return             SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_ecp_gen_sprk(pufs_ka_slot_t slot,
                                pufs_rt_slot_t pufslot,
                                const uint8_t *salt,
                                uint32_t saltlen,
                                const uint8_t *info,
                                uint32_t infolen,
                                pufs_hash_t hash);
/**
 * @brief Generate ephemeral ECC private key.
 *
 * @param[in] slot  Private key slot.
 * @return          SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_ecp_gen_eprk(pufs_ka_slot_t slot);
/**
 * @brief Generate ECC public key of the corresponding private key.
 *
 * @param[out] puk      Public key.
 * @param[in]  prktype  Private key type.
 * @param[in]  prkslot  Private key slot.
 * @return              SUCCESS on success, otherwise an error code.
 *
 * @note Only \ref PRKEY and \ref OTPKEY are allowed \em keytype.
 */
pufs_status_t pufs_ecp_gen_puk(pufs_ec_point_st *puk,
                               pufs_key_type_t prktype,
                               uint32_t prkslot);
/**
 * @brief Validate ECC public key.
 *
 * @param[in] puk   ECC public key.
 * @param[in] full  A flag to enable full validation.
 * @return          SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_ecp_validate_puk(pufs_ec_point_st puk, bool full);
/**
 * @brief Derive shared secret from ephemeral keys by ECC CDH.
 *
 * @param[in]  puk      Public key.
 * @param[in]  prkslot  Private key slot.
 * @param[out] ss       Shared secret. ss can be NULL.
 * @return              SUCCESS on success, otherwise an error code.
 * FIXME: Add explanation on when ss should be NULL.
 */
pufs_status_t pufs_ecp_ecccdh_2e(pufs_ec_point_st puk,
                                 pufs_ka_slot_t prkslot,
                                 uint8_t *ss);
/**
 * @brief Derive shared secret from ephemeral and static keys by ECC CDH.
 *
 * @param[in]  puk_e      Ephemeral public key.
 * @param[in]  puk_s      Static public key.
 * @param[in]  prkslot_e  Ephemeral private key slot.
 * @param[in]  prktype_s  Static private key type.
 * @param[in]  prkslot_s  Static private key slot.
 * @param[out] ss         Shared secret. ss can be NULL.
 * @return                SUCCESS on success, otherwise an error code.
 *
 * @note Only \ref PRKEY and \ref OTPKEY are allowed \em keytype.
 * FIXME: Add explanation on when ss should be NULL.
 */
pufs_status_t pufs_ecp_ecccdh_2e2s(pufs_ec_point_st puk_e,
                                   pufs_ec_point_st puk_s,
                                   pufs_ka_slot_t prkslot_e,
                                   pufs_key_type_t prktype_s,
                                   uint32_t prkslot_s,
                                   uint8_t *ss);
/**
 * @brief Verify the ECDSA signature of the message digest.
 *
 * @param[in] sig  Signature.
 * @param[in] md   Message digest.
 * @param[in] puk  Public key for signature verification.
 * @return         SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_ecp_ecdsa_verify_dgst(pufs_ecdsa_sig_st sig,
                                         pufs_dgst_st md,
                                         pufs_ec_point_st puk);
/**
 * @brief Generate an ECDSA signature from a message digest.
 *
 * @param[in] sig      Signature.
 * @param[in] md       Message digest.
 * @param[in] prktype  Private key type.
 * @param[in] prkslot  Private key slot.
 * @param[in] k        Random k only used in CAVP. k can be NULL.
 * @return             SUCCESS on success, otherwise an error code.
 *
 * @note Only \ref PRKEY and \ref OTPKEY are allowed \em keytype.
 * FIXME: Add explanation on when k shoud be NULL.
 */
pufs_status_t pufs_ecp_ecdsa_sign_dgst(pufs_ecdsa_sig_st *sig,
                                       pufs_dgst_st md,
                                       pufs_key_type_t prktype,
                                       uint32_t prkslot,
                                       const uint8_t *k);
/**
 * @brief RSA verification.
 *
 * @param[in] sig      RSA signature.
 * @param[in] rsatype  RSA type.
 * @param[in] n        RSA parameter n.
 * @param[in] puk      RSA public key.
 * @param[in] msg      Message.
 * @return             SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_rsa_verify(const uint8_t *sig,
                              pufs_rsa_type_t rsatype,
                              const uint8_t *n,
                              uint32_t puk,
                              const uint8_t *msg);
/**
 * @brief RSA signing.
 *
 * @param[out] sig      RSA signature.
 * @param[in]  rsatype  RSA type.
 * @param[in]  n        RSA parameter n.
 * @param[in]  puk      RSA public key.
 * @param[in]  prk      RSA private key.
 * @param[in]  msg      Message.
 * @param[in]  phi      The value of Euler totient function of RSA parameter n.
 *                      phi can be NULL.
 *
 * @return              SUCCESS on success, otherwise an error code.
 * FIXME: Add explanation on when phi can be NULL
 */
pufs_status_t pufs_rsa_sign(uint8_t *sig,
                            pufs_rsa_type_t rsatype,
                            const uint8_t *n,
                            uint32_t puk,
                            const uint8_t *prk,
                            const uint8_t *msg,
                            const uint8_t *phi);
#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /*__PUFS_PKC_H__*/
