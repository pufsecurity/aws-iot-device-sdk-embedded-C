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
 *@file        ecdh_alt.c
 *
 *@brief       ecdsa alternative wrapper functions for Elliptic curve Diffie-Hellman
 *
 *             References:
 *             SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 *             RFC 4492
 *
 *@copyright   2023-2024 PUFsecurity
 *
 ***************************************************************************************/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif



#if defined(MBEDTLS_ECDH_C)


#include <string.h>

#include "pufs_mbedtls_ecdh.h"

#if defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT)

/*
 * Generate public key: simple wrapper around mbedtls_ecp_gen_keypair
 */
int mbedtls_ecdh_gen_public( mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng )
{

    int ret;

    PUFS_LOG_WRAP_FUNC("pufs mbedtls_ecdh_gen_public alt\n");

    ret = pufs_mbedtls_ecdh_gen_public( grp, d, Q, f_rng, p_rng );

    return ( ret );
}
#endif /* MBEDTLS_ECDH_GEN_PUBLIC_ALT */

#if defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
/*
 * Compute shared secret (SEC1 3.3.1)
 */
int mbedtls_ecdh_compute_shared( mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                 const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng )
{
    int ret;

    PUFS_LOG_WRAP_FUNC("pufs mbedtls_ecdh_compute_shared alt\n");

    ret = pufs_mbedtls_ecdh_compute_shared( grp, z, Q, d, f_rng, p_rng );
    return ( ret );
}
#endif /* MBEDTLS_ECDH_COMPUTE_SHARED_ALT */

#endif /* ECDH_ALT_C */
