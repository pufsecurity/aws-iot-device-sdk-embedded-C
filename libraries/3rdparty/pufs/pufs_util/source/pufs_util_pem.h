/***********************************************************************************
 *
 *  Copyright (c) 2023-2024, PUFsecurity
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *  3. Neither the name of PUFsecurity nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 *  OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 *  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **************************************************************************************/


/*!*************************************************************************************
 *
 *@file        pufs_util_pem.h
 *
 *@brief       pufs_util pem header file
 *
 *@copyright   2023-2024 PUFsecurity
 *
 ***************************************************************************************/


#ifndef __PUFS_UTIL_PEM_H__
#define __PUFS_UTIL_PEM_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef PUFSE_HOST
#include "pufs_basic.h"
#else
#include "pufs_common.h"
#endif

#include "pufs_util_common.h"
#include "pufs_util_sec.h"
#include "mbedtls/oid.h"

/*****************************************************************************
 * Enumerations
 ****************************************************************************/

/*****************************************************************************
 * API functions
 ****************************************************************************/

/*****************************************************************************
 * Function Declaration
 ****************************************************************************/

int pufs_util_ecp_point_write_binary( pufs_ec_point_st *kpub,
                                      int format, size_t *olen,
                                      unsigned char *buf, size_t buflen );

#if 0
static int pufs_util_write_ec_pubkey( unsigned char **p, unsigned char *start,
                                      pufs_ec_point_st *kpub );

static int pk_write_ec_param( unsigned char **p, unsigned char *start,
                              mbedtls_ecp_group_id gid);
#endif

int pufs_util_write_ec_pubkey_der( pufs_ec_point_st *kpub, unsigned char *buf, size_t size,
                                   mbedtls_ecp_group_id gid);


int mbedtls_pem_write_buffer( const char *header, const char *footer,
                              const unsigned char *der_data, size_t der_len,
                              unsigned char *buf, size_t buf_len, size_t *olen );

int pufs_util_write_ecdsa_pubkey_pem( pufs_ec_point_st *key, unsigned char *buf, size_t size, mbedtls_ecp_group_id gid);

#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /* __PUFS_UTIL_PEM_H__ */
