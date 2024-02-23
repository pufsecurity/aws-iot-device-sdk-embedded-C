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
 *@file        gcm_alt.h
 *
 *@brief       header file of gcm alternative wrapper functions
 *
 *             Below information is from mbedtls/include/mbedtls/gcm.h:
 *
 *             The Galois/Counter Mode (GCM) for 128-bit block ciphers is defined
 *             in <em>D. McGrew, J. Viega, The Galois/Counter Mode of Operation
 *             (GCM), Natl. Inst. Stand. Technol.</em>
 *
 *             For more information on GCM, see <em>NIST SP 800-38D: Recommendation for
 *             Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC</em>.
 *
 *@copyright   2023-2024 PUFsecurity
 *
 ***************************************************************************************/


#ifndef GCM_ALT_H
#define GCM_ALT_H


#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdint.h>
#include "common_alt.h"
//#include "pufs_util_log.h"




#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_GCM_ALT)

#include "pufs_sp38d_internal.h"
#include "pufs_sp38d.h"


/**
 * \brief          The GCM context structure.
 */
#define GCM_CTX_SIZE_IN_BYTES  sizeof(pufs_sp38d_ctx)
typedef struct mbedtls_gcm_context_t
{

    mbedtls_cipher_context_t cipher_ctx;  /*!< The cipher context used. */
    uint8_t buff[GCM_CTX_SIZE_IN_BYTES];  /*!< Internal buffer */
    unsigned char key[32];                /*!< Key address */
    uint32_t keybits;                     /*!< Key bits */
    uint8_t  *output_addr;                 /*!< Output buffer address */
    uint64_t len;                         /*!< The total length of the encrypted data. */
    uint64_t add_len;                     /*!< The total length of the additional data. */
    int mode;                             /*!< The operation to perform:
                                           #MBEDTLS_GCM_ENCRYPT or
                                           #MBEDTLS_GCM_DECRYPT. */

} mbedtls_gcm_context;

#endif /* MBEDTLS_GCM_ALT */


#ifdef __cplusplus
}
#endif


#endif /* gcm_alt.h */
