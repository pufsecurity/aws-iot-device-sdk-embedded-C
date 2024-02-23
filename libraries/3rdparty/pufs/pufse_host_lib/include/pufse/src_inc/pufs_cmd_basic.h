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
 * @file      pufs_cmd_basic.h
 * @brief     PUFsecurity cmd basic handle interface
 * @copyright 2023 PUFsecurity
 */
#ifndef __PUFS_CMD_BASIC_H__
#define __PUFS_CMD_BASIC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <hal_common.h>
#include "pufs_basic.h"

/*****************************************************************************
 * Macros
 ****************************************************************************/
/**
* @brief  Size of command crc data in bytes.
*/
#define CMD_CRC_SIZE             (0x02)
/**
* @brief  Size of max command payload in bytes.
*/
#define CMD_MAX_PAYLOAD_SIZE     (0x900)//2304 bytes
/**
* @brief  Size of error response in bytes.
*/
#define CMD_ERROR_RESPONSE_SIZE  (0x05)
/**
* @brief  Command receive message TAG.
*/
#define CMD_RCVD_TAG             (0xEF)
/**
* @brief  Command respond message TAG.
*/
#define CMD_RESP_TAG             (0xD6)
/**
* @brief  Size of max sw key max length in bytes
*/
#define SW_KEY_MAXLEN            (0x40)
/**
* @brief  CRC16-CCITT polynomial: x^16 + x^12 + x^5 + 1 (0x1021)
*/
#define CRC16_POLY               (0x1021)
/**
* @brief  Mailbox Buffer Size
*/
#define MAILBOX_BUFFER_SIZE      (0x940)
/*****************************************************************************
 * Enumerations
 ****************************************************************************/
/**
 * @brief Command cmdcode list
 */
typedef enum {
    CMD_CODE_PUFRT    = 0x00, ///< PUFrt
    CMD_CODE_KA       = 0x01, ///< KA(Key Array)
    CMD_CODE_HMAC     = 0x02, ///< HMAC/Hash
    CMD_CODE_CMAC     = 0x03, ///< CMAC
    CMD_CODE_KDF      = 0x04, ///< KDF
    CMD_CODE_MO       = 0x05, ///< MO encrypt/decrypt
    CMD_CODE_DRBG     = 0x06, ///< DRBG
    CMD_CODE_PKC      = 0x07, ///< ECC
    CMD_CODE_CHACHA   = 0x08, ///< CHACHA
} cmd_cmdcode_t;
/**
 * @brief Command feature list for AES operation
 */
typedef enum {
    CMD_SP38A_INIT    = 0x00,
    CMD_SP38A_UPDATE  = 0x01,
    CMD_SP38A_FINAL   = 0x02,
    CMD_SP38E_INIT    = 0x03,
    CMD_SP38E_UPDATE  = 0x04,
    CMD_SP38E_FINAL   = 0x05,
    CMD_SP38C_INIT    = 0x06,
    CMD_SP38C_UPDATE  = 0x07,
    CMD_SP38C_FINAL   = 0x08,
    CMD_SP38D_INIT    = 0x09,
    CMD_SP38D_UPDATE  = 0x0A,
    CMD_SP38D_FINAL   = 0x0B,
} cmd_mo_feature_t;
/**
 * @brief SP39A mode list
 */
typedef enum {
    CMD_DECRYPT       = 0x00,
    CMD_ENCYRPT       = 0x01
} cmd_mo_crypt_t;
/*****************************************************************************
 * Structures
 ****************************************************************************/
/**
 * @brief Data structure of command header.
 */
typedef struct __attribute__((packed))
{
    uint16_t size;                                 ///< total command packet size in bytes
    uint8_t tag;                                   ///< tag to check rx/tx size is correct
    uint8_t cmdcode;                               ///< command operation code
    uint8_t feature;                               ///< feature field values
    uint8_t status;                                ///< response Status
}
cmd_header_t;

/**
 * @brief Data structure of command crc.
 */
typedef struct __attribute__((packed))
{
    uint8_t data[CMD_CRC_SIZE];                    ///< crc data
}
cmd_crc_t;

/**
 * @brief Data structure of command message.
 */
typedef struct __attribute__((packed))
{
    cmd_header_t header;                           ///< cmd header
    uint8_t      payload[CMD_MAX_PAYLOAD_SIZE];    ///< command data payload
    cmd_crc_t    crc;                              ///< crc data
}
cmd_t;

/**
 * @brief Data structure of command error respond message.
 */
typedef struct __attribute__((packed))
{
    cmd_header_t header;                            ///< cmd header
    cmd_crc_t crc;                                  ///< crc data
}
cmd_error_cpl_t;

/*****************************************************************************
 * API functions
 ****************************************************************************/
/**
 * @brief Check CRC for the incoming command message
 *
 * @return                  command buffer pointer.
 */
cmd_t* cmd_buf_ptr_get(void);
/**
 * @brief Check CRC for the incoming command message
 *
 * @param[in] in_msg        Incoming command message
 * @return                  PUFS_SUCCESS on success, otherwise an error code.
 */
pufs_status_t cmd_crc_check(const cmd_t *in_msg);
/**
 * @brief Calculate CRC for the outgoing command message
 *
 * @param[in,out] out_msg   Outgoing command message
 * @return                  PUFS_SUCCESS on success, otherwise an error code.
 */
pufs_status_t cmd_crc_calc(cmd_t *out_msg);
/**
 * @brief Execute security commands to PUFse device
 *
 * @param[in,out] packet    Transfer/Receive command message
 * @param[in] rxsize        Receive message size in bytes
 * @return                  PUFS_SUCCESS on success, otherwise an error code.
 */
pufs_status_t cmd_execution(cmd_t *packet, uint16_t rx_size);
/**
 * @brief Initialize outgoing command message header
 *
 * @param[out] out_msg      Outgoing command message
 * @param[in] size          Outgoing message size in bytes
 * @param[in] tag           Outgoing message tag
 * @param[in] cmdcode       Outgoing message command code
 * @param[in] feature       Outgoing message command feature
 */
void cmd_header_init(cmd_header_t *out_msg, uint16_t size, uint8_t tag,
                     uint8_t cmdcode, uint8_t feature);
#endif /*__PUFS_CMD_BASIC_H__*/
