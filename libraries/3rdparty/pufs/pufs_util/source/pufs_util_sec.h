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
 *@file        pufs_util_sec.h
 *
 *@brief       pufs_util secure module related functions
 *
 *@copyright   2023-2024 PUFsecurity
 *
 ***************************************************************************************/


#ifndef __PUFS_UTIL_SEC_H__
#define __PUFS_UTIL_SEC_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef PUFSE_HOST

#include "pufs_basic.h"
#include "pufs_pkc.h" //pufs_ec_point_st

#else

#include "pufs_common.h"
#include "pufs_ecp.h" //pufs_ec_point_st

#endif /* PUFSE_HOST */

#include "pufs_util_common.h"


/*****************************************************************************
 * Macro
 ****************************************************************************/
#define RNG_BLK_SIZE_BIT            32                           //Rng block size in bits
#define RNG_BLK_SIZE_BYTE           (RNG_BLK_SIZE_BIT/8)         //Rng block size in bytes
#define BIT_TO_RNG_BLK(b)           ((b + RNG_BLK_SIZE_BIT - 1)/RNG_BLK_SIZE_BIT)

#ifdef RANDOM_IN_BYTE
#define BYTE_TO_RNG_BLK(B)           ((B + RNG_BLK_SIZE_BYTE - 1)/RNG_BLK_SIZE_BYTE)
#endif


#ifdef PUFSE_HOST
//Use the same define name to set sha_256/sha_224 algorithm in pufs_util_sec.c functions
//regardless of whether building pufcc or pufse host library
#define SHA_256                      PUFSE_SHA_256
#endif

/*****************************************************************************
 * Enumerations
 ****************************************************************************/
/**
 * @enum  pufs_util_sec_key_algo
 * @brief support key generation algorithm
 */
typedef enum pufs_util_sec_key_algo
{
    SEC_KEY_ECDSAP256,
    SEC_KEY_NULL
} pufs_util_sec_key_algo_t;


/*****************************************************************************
 * Structure definition
 ****************************************************************************/


/*****************************************************************************
 * API functions
 ****************************************************************************/


/*****************************************************************************
 * Function Declaration
 ****************************************************************************/
rt_status_t pufs_util_sec_module_init(void);
rt_status_t pufs_util_sec_module_release(void);

void pufs_util_sec_read_uid_puf(void);
void pufs_util_sec_enroll_puf(void);

rt_status_t pufs_util_sec_gen_ecdsa_key(pufs_util_sec_key_algo_t algo,
                                        uint8_t *p_kprv_slot, pufs_ec_point_st *p_kpub);
rt_status_t pufs_util_sec_export_wrapped_priv_key(uint8_t *p_kprv_slot, uint8_t *out, uint32_t size);
rt_status_t pufs_util_sec_import_wrapped_priv_key_test(uint8_t *wrapped_key, uint32_t key_size);
rt_status_t pufs_util_sec_clear_used_key_slot(void);

#ifdef SIGN_CMD_SUPPORT
rt_status_t pufs_util_sec_sha256(uint8_t *p_out_buf_32bytes, uint8_t *p_in_buf, uint32_t in_buf_len);
rt_status_t pufs_util_sec_gen_ecdsa_sig( uint8_t *p_sig, uint32_t *p_sig_len,
                                         pufs_util_sec_key_algo_t algo, uint8_t *p_kprv_slot,
                                         uint8_t *p_md, uint32_t md_len);

#endif

rt_status_t pufs_util_sec_gen_rn_bytes(uint8_t *p_out, uint32_t *p_len, uint32_t rn_len);

#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /* __PUFS_UTIL_SEC_H__ */
