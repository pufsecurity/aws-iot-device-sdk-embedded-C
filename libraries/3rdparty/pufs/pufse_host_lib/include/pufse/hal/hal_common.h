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
 * @file      hal_common.h
 * @brief     PUFsecurity commmon HAL interface
 * @copyright 2023 PUFsecurity
 */

#ifndef __HAL_COMMON_H__
#define __HAL_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "pufs_basic.h"
/*****************************************************************************
 * Enumerations
 ****************************************************************************/
/**
 * @brief Interface HAL type
 */
typedef enum {
    HAL_INTERFACE_UART,                                                  ///< UART interface
    HAL_INTERFACE_USB,                                                   ///< USB interface
} iface_type_t;
/*****************************************************************************
 * Structure
 ****************************************************************************/
/**
 * @brief PUFse Device Interface configuration
 */
typedef struct hal_iface_ctx {
    iface_type_t type;                                                    ///< active iface - how to interpret the union below
    struct {
        pufs_status_t (*init)(struct hal_iface_ctx *iface);               ///< init the communicate interface with PUFse
        pufs_status_t (*send)(struct hal_iface_ctx *iface,                ///< send data through pheriperal interface
                              uint8_t *txdata, uint16_t txlength);
        pufs_status_t (*receive)(struct hal_iface_ctx *iface,             ///< receive data fro pheriperal interface
                                 uint8_t *rxdata, uint16_t *rxlength);
        pufs_status_t (*deinit)(void *hal_data);                          ///< deinit the communitae interface with PUFse
    } hal;
    union {                                                               ///< each instance of an iface cfg defines a single type of interface
        struct {
            uint8_t     port;                                             ///< Port numbers where supported - otherwise accept the device through config data
            uint32_t    baud;                                             ///< typically 115200
            uint8_t     wordsize;                                         ///< usually 8
            uint8_t     parity;                                           ///< 0 == even, 1 == odd, 2 == none
            uint8_t     stopbits;                                         ///< 0,1,2
        } uart;
        struct {
            uint32_t    vid;                                              ///< Vendor ID of kit (0x03EB for CK101)
            uint32_t    pid;                                              ///< Product ID of kit (0x2312 for CK101)
            uint32_t    packetsize;                                       ///< Size of the USB packet
        } hid;
    } cfg;
    int      rx_retries;                                                  ///< the number of retries to attempt for receiving bytes
    void    *hal_data;                                                    ///< opaque data used by HAL in device discovery
} hal_iface_ctx;
#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /* __HAL_COMMON_H__ */
