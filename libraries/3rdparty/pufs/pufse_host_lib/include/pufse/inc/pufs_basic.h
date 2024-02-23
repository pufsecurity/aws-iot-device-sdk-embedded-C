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
 * @file      pufs_basic.h
 * @brief     PUFsecurity basic API interface
 * @copyright 2023 PUFsecurity
 */
#ifndef __PUFS_BASIC_H__
#define __PUFS_BASIC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
/*****************************************************************************
 * Macros
 ****************************************************************************/
/**
 * @brief Convert number of bits to number of bytes
 *
 * @param[in] bits  Number of bits.
 * @return          Number of bytes.
 */
#define b2B(bits) (((bits) + 7) / 8)
/**
 * @brief Convert number of bytes to number of bits
 *
 * @param[in] len  Number of bytes.
 * @return         Number of bits.
 */
#define B2b(len) (8 * (len))
/**
 * @brief Convert test cases parameters
 *
 * @param[in] type  Type of test cases.
 * @param[in] var   Test case variable.
 * @return          num, var
 */
#define TCPARAM(type, var) (sizeof(var) / sizeof(type)), (var)
/**
 * @brief Block size in bytes of block cipher algorithms
 */
#define BC_BLOCK_SIZE 16
/*****************************************************************************
 * Enumerations
 ****************************************************************************/
/**
 * @brief Block cipher algorithm.
 */
typedef enum {
    AES,        ///< AES
    SM4,        ///< SM4
    CHACHA,     ///< CHACHA
    N_CIPHER_T, // keep in the last one
} pufs_cipher_t;

/**
 * @brief Status code
 */
typedef enum {
    SUCCESS,                /**< Success. */
    E_ALIGN,                /**< Address alignment mismatch. */
    E_OVERFLOW,             /**< Space overflow. */
    E_UNDERFLOW,            /**< Size too small. */
    E_INVALID,              /**< Invalid argument. */
    E_BUSY,                 /**< Resource is occupied. */
    E_UNAVAIL,              /**< Resource is unavailable. */
    E_FIRMWARE,             /**< Firmware error. */
    E_VERFAIL,              /**< Invalid public key or digital signature. */
    E_ECMPROG,              /**< Invalid ECC microprogram. */
    E_DENY,                 /**< Access denied. */
    E_UNSUPPORT,            /**< Not support. */
    E_INFINITY,             /**< Point at infinity. */
    E_ERROR,                /**< Unspecific error. */
    /* Interface Error */
    E_IFACE_INIT_FAIL,
    E_IFACE_NOT_INIT,
    E_IFACE_BAD_PARAM,
    E_IFACE_COMM_FAIL,
    E_IFACE_TX_FAIL,
    E_IFACE_RX_FAIL,
    /* Command Error */
    E_CMD_BAD_PARAM,
    E_CMD_BAD_RETURN_PARAM,

} pufs_status_t;
/*****************************************************************************
 * Structures
 ****************************************************************************/
/**
 * @brief Maximum message digest length in bytes.
 */
#ifndef DLEN_MAX
#define DLEN_MAX 64
#endif
/**
 * @brief Message digest structure.
 */
typedef struct {
    uint32_t dlen;          ///< Current message digest length in bytes.
    uint8_t dgst[DLEN_MAX]; ///< Message digest.
} pufs_dgst_st;
/*****************************************************************************
 * API functions
 ****************************************************************************/
/**
 * @brief PUFse device interface initial configuration.
 *
 * @return SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_cmd_iface_init(void);
/**
 * @brief PUFse device interface de-initial configuration.
 *
 * @return SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_cmd_iface_deinit(void);
#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /*__PUFS_BASIC_H__*/
