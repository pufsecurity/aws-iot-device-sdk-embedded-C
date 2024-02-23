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
 * @brief     PUFsecurity HMAC command handle interface
 * @copyright 2023 PUFsecurity
 */
#ifndef __PUFS_CMD_HMAC_H__
#define __PUFS_CMD_HMAC_H__

#include "pufs_cmd_basic.h"
#include "pufs_hmac.h"
/*****************************************************************************
 * Macros
 ****************************************************************************/
/**
* @brief  max HMAC block size in bytes
*/
#define MAX_HMAC_BLOCK_SIZE     (0x80)
/**
* @brief  max HMAC SWKEY size in bytes
*/
#define MAX_HMAC_SWKEY_SIZE      (0xA0)
/*****************************************************************************
 * Enumerations
 ****************************************************************************/
/**
 * @brief Command feature list for HMAC
 */
typedef enum {
    CMD_HASH_INIT               = 0x00,
    CMD_HASH_UPDATE             = 0x01,
    CMD_HASH_FINAL              = 0x02,
    CMD_HMAC_INIT               = 0x03,
    CMD_HMAC_UPDATE             = 0x04,
    CMD_HMAC_FINAL              = 0x05,
} cmd_hmac_feature_t;
/*****************************************************************************
 * Macros
 ****************************************************************************/
/*****************************************************************************
 * Structures
 ****************************************************************************/
/**
* @brief Data structure of pufs hmac context
*/
struct pufs_hmac_context {
    uint32_t blocklen;                      ///< hmac blk length in bytes
    uint32_t curlen;                        ///< Number of bytes in current blk
    uint8_t  buff[MAX_HMAC_BLOCK_SIZE];     ///< Unprocessed message storage
};

/**
* @brief Data structure of cmd receive message: hash init
*/
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint8_t hash;                           ///< hash algorithms
    cmd_crc_t crc;                          ///< command crc
}
cmd_hash_init_t;

/**
* @brief Data structure of cmd respond message: hash init
*/
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    cmd_crc_t crc;                          ///< command crc
}
cmd_hash_init_cpl_t;

/**
* @brief Data structure of cmd receive message: hash update
*/
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint32_t msglen;                        ///< message length in bytes
    uint8_t msg[MAX_HMAC_BLOCK_SIZE];       ///< message content
    cmd_crc_t crc;                          ///< command crc
}
cmd_hash_update_t;

/**
* @brief Data structure of cmd respond message: hash update
*/
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    cmd_crc_t crc;                          ///< command crc
}
cmd_hash_update_cpl_t;

/**
* @brief Data structure of cmd receive message: hash final
*/
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    cmd_crc_t crc;                          ///< command crc
}
cmd_hash_final_t;

/**
* @brief Data structure of cmd respond message: hash final
*/
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint8_t dlen;                           ///< digest length in bytes
    uint8_t md[DLEN_MAX];                   ///< message digest
    cmd_crc_t crc;                          ///< command crc
}
cmd_hash_final_cpl_t;

/**
* @brief Data structure of cmd respond message: hmac
*/
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint8_t dlen;                           ///< digest length in bytes
    uint8_t md[DLEN_MAX];                   ///< message digest
    cmd_crc_t crc;                          ///< command crc
}
cmd_hmac_cpl_t;

/**
* @brief Data structure of cmd receive message: hmac init
*/
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint8_t hash;                           ///< hash algorithms
    uint8_t keytype;                        ///< key type
    uint8_t slot;                           ///< key slot
    uint32_t keybits;                       ///< key length in bits
    uint8_t key[MAX_HMAC_SWKEY_SIZE];       ///< key
    cmd_crc_t crc;                          ///< command crc
}
cmd_hmac_init_t;

/**
* @brief Data structure of cmd respond message: hmac init
*/
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    cmd_crc_t crc;                          ///< command crc
}
cmd_hmac_init_cpl_t;

/**
* @brief Data structure of cmd receive message: hmac update
*/
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint32_t msglen;                        ///< message length in bytes
    uint8_t msg[MAX_HMAC_BLOCK_SIZE];       ///< message content
    cmd_crc_t crc;                          ///< command crc
}
cmd_hmac_update_t;

/**
* @brief Data structure of cmd respond message: hmac update
*/
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    cmd_crc_t crc;                          ///< command crc
}
cmd_hmac_update_cpl_t;

/**
* @brief Data structure of cmd receive message: hmac final
*/
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint32_t msglen;                        ///< message length in bytes
    uint8_t msg[MAX_HMAC_BLOCK_SIZE];       ///< message content
    cmd_crc_t crc;                          ///< command crc
}
cmd_hmac_final_t;

/**
* @brief Data structure of cmd respond message: hmac final
*/
typedef struct __attribute__((packed))
{
    cmd_header_t header;                    ///< command packet header
    uint8_t dlen;                           ///< digest length in bytes
    uint8_t md[DLEN_MAX];                   ///< message digest
    cmd_crc_t crc;                          ///< command crc
}
cmd_hmac_final_cpl_t;
/*****************************************************************************
 * Internal functions
 ****************************************************************************/
#endif /*__PUFS_CMD_HMAC_H__*/
