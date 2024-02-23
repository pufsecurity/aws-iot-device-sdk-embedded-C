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
 * @file      hal_usb_hid.h
 * @brief     PUFsecurity HAL USB HID interface
 * @copyright 2023 PUFsecurity
 */
#ifndef __HAL_USB_HID_H__
#define __HAL_USB_HID_H__

#ifdef __cplusplus
extern "C" {
#endif
/*****************************************************************************
 * Macros
 ****************************************************************************/
/**
* @brief  TaiWon vendor ID = FF08h(Fake)
*/
#define USBD_VENDOR_ID          (0xFF08u)
/**
* @brief  Product ID: 9001h = project code
*/
#define USBD_PRODUCT_ID         (0x9001u)
/**
* @brief  max USB hid transfer size
*/
#define MAX_USB_HID_SIZE        (64)
/*****************************************************************************
 * internal functions
 ****************************************************************************/
/**
 * @brief initial the usb hid HAL to communicate with PUFse device
 *
 * @param[in] iface      The context of usb hid HAL interface
 * @return               SUCCESS on success, otherwise an error code.
 *
 */
pufs_status_t usb_hid_init(hal_iface_ctx *iface);
/**
 * @brief usb hid HAL to send data packet to PUFse device
 *
 * @param[in] iface      The context of usb hid HAL interface
 * @param[in] tx_buf     Data buffer to send
 * @param[in] tx_size    Data length in bytes to send
 * @return               SUCCESS on success, otherwise an error code.
 *
 */
pufs_status_t usb_hid_send(hal_iface_ctx *iface, uint8_t *tx_buf,
                           uint16_t tx_size);
/**
 * @brief usb hid HAL to receive data packet from PUFse device
 *
 * @param[in] iface      The context of usb hid HAL interface
 * @param[in] rx_buf     Data buffer to receive
 * @param[in] rx_size    Data length in bytes to send
 * @return               SUCCESS on success, otherwise an error code.
 *
 */
pufs_status_t usb_hid_receive(hal_iface_ctx *iface, uint8_t *rx_buf,
                              uint16_t *rx_size);
/**
 * @brief deinit the usb hid HAL to communicate with PUFse device
 *
 * @param[in] hal_data  hid device data
 * @return              SUCCESS on success, otherwise an error code.
 *
 */
pufs_status_t usb_hid_deinit(void *hal_data);
#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /* __HAL_USB_HID_H__ */
