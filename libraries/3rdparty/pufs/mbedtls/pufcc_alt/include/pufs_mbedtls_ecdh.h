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
 *@file        pufs_mbedtls_ecdh.h
 *
 *@brief       This file contains PUFsecurity crypto ECDH definitions and functions for mbedtls.
 *
 *             References:
 *             SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 *             RFC 4492
 *
 *
 *@copyright   2023-2024 PUFsecurity
 *
 ***************************************************************************************/

#ifndef PUFS_MBEDTLS_ECDH_H
#define PUFS_MBEDTLS_ECDH_H

#include "mbedtls/ecp.h"
#include "common_alt.h"


#ifdef __cplusplus
extern "C" {
#endif



/**
 * \brief           This function generates an ECDH keypair on an elliptic
 *                  curve.
 *
 *                  This function performs the first of two core computations
 *                  implemented during the ECDH key exchange. The second core
 *                  computation is performed by pufs_mbedtls_ecdh_compute_shared().
 *
 * \see             ecp.h
 *
 * \param grp       The ECP group.
 * \param d         The destination MPI (private key).
 * \param Q         The destination point (public key).
 * \param f_rng     The RNG function.
 * \param p_rng     The RNG context.
 *
 * \return          \c 0 on success.
 * \return          An \c MBEDTLS_ERR_ECP_XXX or
 *                  \c MBEDTLS_MPI_XXX error code on failure.
 *
 */
int pufs_mbedtls_ecdh_gen_public( mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng );

/**
 * \brief           This function computes the shared secret.
 *
 *                  This function performs the second of two core computations
 *                  implemented during the ECDH key exchange. The first core
 *                  computation is performed by pugcc_mbedtls_ecdh_gen_public().
 *
 * \see             ecp.h
 *
 * \note            If \p f_rng is not NULL, it is used to implement
 *                  countermeasures against side-channel attacks.
 *                  For more information, see mbedtls_ecp_mul().
 *
 * \param grp       The ECP group.
 * \param z         The destination MPI (shared secret).
 * \param Q         The public key from another party.
 * \param d         Our secret exponent (private key).
 * \param f_rng     The RNG function.
 * \param p_rng     The RNG context.
 *
 * \return          \c 0 on success.
 * \return          An \c MBEDTLS_ERR_ECP_XXX or
 *                  \c MBEDTLS_MPI_XXX error code on failure.
 */
int pufs_mbedtls_ecdh_compute_shared( mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                      const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                      int (*f_rng)(void *, unsigned char *, size_t),
                                      void *p_rng );



#ifdef __cplusplus
}
#endif

#endif /* pufs_mbedtls_ecdh.h */
