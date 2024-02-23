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
 * @file      pufs_cmd_sp38d.h
 * @brief     PUFsecurity sp38d command handle interface
 * @copyright 2023 PUFsecurity
 */
#ifndef __PUFS_CMD_SP38D_H__
#define __PUFS_CMD_SP38D_H__

#include "pufs_cmd_basic.h"
#include "pufs_sp38d.h"
/*****************************************************************************
 * Macros
 ****************************************************************************/
/**
* @brief  Size of max tag length in bytes.
*/
#define CMD_MAX_SP38D_TAG_SIZE    (16)
/**
* @brief  Size of max iv length in bytes.
*/
#define CMD_MAX_SP38D_IV_SIZE     (128)
/*****************************************************************************
 * Enumerations
 ****************************************************************************/
/**
 * enum type for CCM input
 */
typedef enum {
    SP38D_NONE,
    SP38D_AAD,
    SP38D_TEXT,
} sp38d_stage;
/*****************************************************************************
 * Structures
 ****************************************************************************/
struct pufs_sp38d_context {
    uint32_t curlen;                        ///< Number of bytes in current block
    uint8_t  buff[BC_BLOCK_SIZE];           ///< Unprocessed message storage
    sp38d_stage stage;
};

/**
 * @brief Data structure of cmd receive message sp38c
 */
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint8_t encrypt;                        ///< encrypt:0x01, decrypt:0x00
    uint8_t cipher;                         ///< block cipher algorithm
    uint8_t keytype;                        ///< key type
    uint8_t keyslot;                        ///< key slot
    uint32_t keybits;                       ///< key length in bits
    uint8_t key[SW_KEY_MAXLEN];             ///< key
    uint8_t ivlen;                          ///< in length in bytes
    uint8_t iv[CMD_MAX_SP38D_IV_SIZE];      ///< iv
    cmd_crc_t crc;                          ///< command crc
}
cmd_sp38d_init_t;

/**
* @brief Data structure of cmd respond message: cmac init
*/
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    cmd_crc_t crc;                          //< command crc
}
cmd_sp38d_init_cpl_t;

/**
 * @brief Data structure of cmd receive message sp38a
 */
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint8_t encrypt;                        ///< encrypt:0x01, decrypt:0x00
    uint8_t aad_update;                     ///< aad update
    uint32_t inlen;                         ///< input data length in bytes
    uint8_t in[BC_BLOCK_SIZE];              ///< input data
    cmd_crc_t crc;                          ///< command crc
}
cmd_sp38d_update_t;

/**
* @brief Data structure of cmd respond message: cmac init
*/
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint8_t outlen;                         ///< output data length in bytes
    uint8_t out[BC_BLOCK_SIZE];             ///< output data
    cmd_crc_t crc;                          ///< command crc
}
cmd_sp38d_update_cpl_t;

/**
 * @brief Data structure of cmd receive message sp38a
 */
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint8_t encrypt;                        ///< encrypt:0x01, decrypt:0x00
    uint32_t taglen;                        ///< tag length in bytes
    uint8_t tag[CMD_MAX_SP38D_TAG_SIZE];    ///< tag data
    cmd_crc_t crc;                          ///< command crc
}
cmd_sp38d_final_t;

/**
* @brief Data structure of cmd respond message: cmac init
*/
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint8_t outlen;                         ///< output data length in bytes
    uint8_t out[BC_BLOCK_SIZE];             ///< output data
    uint8_t tag[CMD_MAX_SP38D_TAG_SIZE];    ///< tag data
    cmd_crc_t crc;                          ///< command crc
}
cmd_sp38d_final_cpl_t;
/*****************************************************************************
 * API functions
 ****************************************************************************/
#endif /*__PUFS_CMD_SP38D_H__*/
