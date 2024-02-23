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
 *@file        pufs_mbedtls_ecdsa.c
 *
 *@brief       Pufsecurity crypto implmentation for Elliptic curve DSA
 *
 *             References:
 *
 *             SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 *
 *@copyright   2023-2024 PUFsecurity
 *
 ***************************************************************************************/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECDSA_C)

#include "mbedtls/ecdsa.h"
#include "mbedtls/asn1write.h"

#include <string.h>

#include "pufs_mbedtls_ecdsa.h"
#include "pufs_common.h"
#include "pufs_ecc.h"
#include "pufs_ecp.h"


int pufs_mbedtls_get_ecname (mbedtls_ecp_group *grp, pufs_ec_name_t *ec_name)
{
    int ret = SUCCESS;
    switch (grp->id)
    {
        case MBEDTLS_ECP_DP_SECP224R1:
            *ec_name = NISTP224;
            break;
        case MBEDTLS_ECP_DP_SECP256R1:
            *ec_name = NISTP256;
            break;

        default:
            ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
            break;
    }
    return ret;
}

#if defined(MBEDTLS_ECDSA_VERIFY_ALT)
/*
 * Verify ECDSA signature of hashed message (SEC1 4.1.4)
 * Obviously, compared to SEC1 4.1.3, we skip step 2 (hash message)
 *
 */
int pufs_mbedtls_ecdsa_verify( mbedtls_ecp_group *grp,
                               const unsigned char *buf, size_t blen,
                               const mbedtls_ecp_point *Q, const mbedtls_mpi *r, const mbedtls_mpi *s)
{

    pufs_dgst_st md;
    pufs_ec_point_st puk;
    pufs_ecdsa_sig_st sig;
    pufs_ec_name_t ec_name = N_ECNAME_T;
    uint32_t x_len, y_len, r_len, s_len;
    pufs_status_t status  = SUCCESS;
    int ret;

    x_len = 0;
    y_len = 0;
    r_len = 0;
    s_len = 0;
    memset(&md, 0, sizeof(pufs_dgst_st));

    PUFS_LOG_FUNC("pufs_mbedtls_ecdsa_verify hashlen:%d\n", blen);

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if ( grp->N.p == NULL )
    {
        return ( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    /*
     * Step 1: make sure r and s are in range 1..n-1
     */
    if ( mbedtls_mpi_cmp_int( r, 1 ) < 0 || mbedtls_mpi_cmp_mpi( r, &grp->N ) >= 0 ||
         mbedtls_mpi_cmp_int( s, 1 ) < 0 || mbedtls_mpi_cmp_mpi( s, &grp->N ) >= 0 )
    {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }


    /*
     * Additional precaution: make sure Q is valid
     */
    MBEDTLS_MPI_CHK( mbedtls_ecp_check_pubkey( grp, Q ) );


#if 1
    ret = pufs_mbedtls_get_ecname(grp, &ec_name);
    if (ret != 0)
    {
        goto cleanup;
    }
#else
    switch (grp->id)
    {
        case MBEDTLS_ECP_DP_SECP224R1:
            ec_name = NISTP224;
            break;
        case MBEDTLS_ECP_DP_SECP256R1:
            ec_name = NISTP256;
            break;

        default:
            ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
            goto cleanup;
            break;
    }
#endif

    //public key length check
    x_len = mbedtls_mpi_size(&(Q->X));
    y_len = mbedtls_mpi_size(&(Q->Y));

    if ((x_len != ecc_param[ec_name].len) || (y_len != ecc_param[ec_name].len))
    {
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
        goto cleanup;
    }

    //Read public key - x, y
    puk.qlen =  ecc_param[ec_name].len;
    if (mbedtls_mpi_write_binary( &(Q->X), puk.x, puk.qlen ) != 0)
    {
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
        goto cleanup;
    }

    if (mbedtls_mpi_write_binary( &(Q->Y), puk.y, puk.qlen ) != 0)
    {
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
        goto cleanup;
    }

    //signature length check, r,s
    r_len = mbedtls_mpi_size(r);
    s_len = mbedtls_mpi_size(s);
    if ((r_len != ecc_param[ec_name].len) || (s_len != ecc_param[ec_name].len))
    {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }
    //Read r,s
    sig.qlen = ecc_param[ec_name].len;
    if (mbedtls_mpi_write_binary( r, sig.r, sig.qlen ) != 0)
    {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    if (mbedtls_mpi_write_binary( s, sig.s, puk.qlen ) != 0)
    {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }


    if ((status = pufs_ecp_set_curve_byname(ec_name)) != SUCCESS)
    {
        ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
        goto cleanup;
    }

    md.dlen = blen;
    memcpy(md.dgst, buf, blen);
    status = pufs_ecp_ecdsa_verify_dgst (sig, md, puk);

    if ((status == E_VERFAIL) || (status == E_INVALID))
    {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }
    else if (status != SUCCESS)
    {
        ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
        goto cleanup;
    }

cleanup:
    if (ret != 0)
    {
        PUFS_LOG_ERR("pufs_mbedtls_ecdsa_verify failed : ret:0x%d, status:%d\n", ret, status);
    }

    return ret;
}
#endif /* MBEDTLS_ECDSA_VERIFY_ALT */


#endif /* PUFS_MBEDTLS_ECDSA_C */
