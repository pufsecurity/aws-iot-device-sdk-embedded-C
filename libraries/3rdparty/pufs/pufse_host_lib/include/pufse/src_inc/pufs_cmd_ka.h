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
 * @file      pufs_cmd_ka.h
 * @brief     PUFsecurity Key Array (KA) command handle interface
 * @copyright 2023 PUFsecurity
 */
#ifndef __PUFS_CMD_KA_H__
#define __PUFS_CMD_KA_H__

#include "pufs_cmd_basic.h"
#include "pufs_ka.h"
/*****************************************************************************
 * Enumerations
 ****************************************************************************/
/**
 * @brief Command feature list for key array (KA)
 */
typedef enum {
    CMD_KA_IMPORT_PLAINTEXT_KEY = 0x00,
    CMD_KA_IMPORT_WRAPPED_KEY   = 0x01,
    CMD_KA_EXPORT_WRAPPED_KEY   = 0x02,
    CMD_KA_CLEAR_KEY_SLOT       = 0x03,
} cmd_ka_feature_t;
/*****************************************************************************
 * Macros
 ****************************************************************************/
/**
* @brief  Command max key array (KA) use key size
*/
#define MAX_CMD_KA_KEY_SIZE      (0x48)
/**
* @brief  Command IV block size
*/
#define MAX_CMD_IV_BLOCK_SIZE    (0x10)
/*****************************************************************************
 * Structures
 ****************************************************************************/
/**
 * @brief Data structure of cmd receive message import plain-text key
 */
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint8_t keytype;                        ///< key type
    uint8_t keyslot;                        ///< key slot
    uint32_t keybits;                       ///< key length in bits
    uint8_t key[MAX_CMD_KA_KEY_SIZE];       ///< key
    cmd_crc_t crc;                          ///< command crc
}
cmd_imp_pt_key_t;

/**
 * @brief Data structure of cmd respond message import plain-text key
 */
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    cmd_crc_t crc;                          ///< command crc
}
cmd_imp_pt_key_cpl_t;

/**
 * @brief Data structure of cmd receive message import wrapped key
 */
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint8_t keytype;                        ///< key type
    uint8_t keyslot;                        ///< key slot
    uint32_t keybits;                       ///< key length in bits
    uint8_t key[MAX_CMD_KA_KEY_SIZE];       ///< key
    uint8_t kekslot;                        ///< KEK key slot
    uint32_t kekbits;                       ///< KEK length in bits
    uint8_t keywrap;                        ///< key wrapping algorithm
    uint8_t iv_enable;                      ///< enable: 0x01/disable: 0x00
    uint8_t iv[MAX_CMD_IV_BLOCK_SIZE];      ///< IV block size
    cmd_crc_t crc;                          ///< command crc
}
cmd_imp_wrapped_key_t;

/**
 * @brief Data structure of cmd respond message import wrapped key
 */
typedef struct __attribute__((packed))
{
    cmd_header_t header;                     ///< command packet header
    cmd_crc_t crc;                           ///< command crc
}
cmd_imp_wrapped_key_cpl_t;

/**
 * @brief Data structure of cmd receive message export wrapped key
 */
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint8_t keytype;                        ///< key type
    uint8_t keyslot;                        ///< key slot
    uint32_t keybits;                       ///< key length in bits
    uint8_t kekslot;                        ///< KEK key slot
    uint32_t kekbits;                       ///< KEK length in bits
    uint8_t keywrap;                        ///< key wrapping algorithm
    uint8_t iv_enable;                      ///< enable: 0x01/disable: 0x00
    uint8_t iv[MAX_CMD_IV_BLOCK_SIZE];      ///< IV block size
    cmd_crc_t crc;                          ///< command crc
}
cmd_exp_wrapped_key_t;

/**
 * @brief Data structure of cmd respond message export wrapped key
 */
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint8_t key[MAX_CMD_KA_KEY_SIZE];       ///< key
    cmd_crc_t crc;                          ///< command crc
}
cmd_exp_wrapped_key_cpl_t;

/**
 * @brief Data structure of cmd receive message clear key slot
 */
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint8_t keytype;                        ///< key type
    uint8_t keyslot;                        ///< key slot
    uint32_t keybits;                       ///< key length in bits
    cmd_crc_t crc;                          ///< command crc
}
cmd_clr_key_slot_t;

/**
 * @brief Data structure of cmd respond message clear key slot
 */
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    cmd_crc_t crc;                          ///< command crc
}
cmd_clr_key_slot_cpl_t;
/*****************************************************************************
 * API functions
 ****************************************************************************/
#endif /*__PUFS_CMD_KA_H__*/
