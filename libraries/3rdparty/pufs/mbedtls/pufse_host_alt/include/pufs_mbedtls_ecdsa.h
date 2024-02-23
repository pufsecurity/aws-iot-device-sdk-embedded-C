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
 *@file        pufs_mbedtls_ecdsa.h
 *
 *@brief       This file contains PPUFsecurity crypto ECDSA definitions and functions for mbedtls.
 *
 *             The Elliptic Curve Digital Signature Algorithm (ECDSA) is defined in
 *             <em>Standards for Efficient Cryptography Group (SECG):
 *             SEC1 Elliptic Curve Cryptography</em>.
 *             The use of ECDSA for TLS is defined in <em>RFC-4492: Elliptic Curve
 *             Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS)</em>.
 *
 *@copyright   2023-2024 PUFsecurity
 *
 ***************************************************************************************/



#ifndef PUFS_MBEDTLS_ECDSA_H
#define PUFS_MBEDTLS_ECDSA_H

#include "mbedtls/ecp.h"
#include "mbedtls/md.h"

#include "pufs_pkc.h"

#include "common_alt.h"


#ifdef __cplusplus
extern "C" {
#endif


/**
 * \brief           This function reads grp id and transfer to corresponding pufs ec_name
 *
 * \param grp       The ECP group pointer.
 * \param ec_name   The ec_name pointer.

 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE if no correspopnding ec_name found
 */
int pufs_mbedtls_get_ecname (mbedtls_ecp_group *grp, pufs_ec_name_t *ec_name);



/**
 * \brief           This function verifies the ECDSA signature of a
 *                  previously-hashed message.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.4, step 3.
 *
 * \see             ecp.h
 *
 * \param grp       The ECP group.
 * \param buf       The message hash.
 * \param blen      The length of \p buf.
 * \param Q         The public key to use for verification.
 * \param r         The first integer of the signature.
 * \param s         The second integer of the signature.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA if the signature
 *                  is invalid.
 * \return          An \c MBEDTLS_ERR_ECP_XXX or \c MBEDTLS_MPI_XXX
 *                  error code on failure for any other reason.
 */
int pufs_mbedtls_ecdsa_verify( mbedtls_ecp_group *grp,
                               const unsigned char *buf, size_t blen,
                               const mbedtls_ecp_point *Q, const mbedtls_mpi *r, const mbedtls_mpi *s);



#ifdef __cplusplus
}
#endif

#endif /* pufs_mbedtls_ecdsa.h */
