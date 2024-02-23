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
 *@file        pufs_mbedtls_ecdh.c
 *
 *@brief       Pufsecurity Crypto implmentation for Elliptic curve Diffie-Hellman
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

#include "mbedtls/ecdh.h"

#include <string.h>

#include "pufs_mbedtls_ecdh.h"
#include "pufs_common.h"
#include "pufs_ecc.h"
#include "pufs_ecp.h"
#include "pufs_mbedtls_ecdsa.h" //for pufs_mbedtls_get_ecname
#include "pufs_ka.h"
#include "pufs_ka_internal.h"    //to do: not use inernal header file.

//Key slot macro and define
#define GET_PRIV_KEY_SLOT_IDX(slot) \
    (((slot >=PRK_0) && (slot <= PRK_2))? (slot-PRK_0) : (0xFE))

//Key slot information bit
#define KEY_VALID_BITMASK        0x00000001 //BIT 0,
#define KEY_VALID_FLAG           0x01UL     // 0: null


#if defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT)
/*
 * Generate public key: simple wrapper around mbedtls_ecp_gen_keypair
 */
int pufs_mbedtls_ecdh_gen_public( mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng )
{

    pufs_status_t status = SUCCESS;
    pufs_ec_name_t ec_name = N_ECNAME_T;
    uint8_t buf[MBEDTLS_MPI_MAX_SIZE];

    pufs_ka_slot_t priv_key_slot = PRK_2; //mqtt ecdsa key used private key 1
    uint8_t  pk_idx = GET_PRIV_KEY_SLOT_IDX(priv_key_slot);
    uint32_t key_status = 0;

    pufs_ec_point_st pub_key;
    size_t size = 0;
    int ret = 0;

    PUFS_MBEDTLS_UNUSED(f_rng);
    PUFS_MBEDTLS_UNUSED(p_rng);


    PUFS_LOG_FUNC("pufs_mbedtls_ecdh_gen_public\n");

    ret = pufs_mbedtls_get_ecname(grp, &ec_name);

    if (ret != 0)
    {
        PUFS_LOG_ERR("pufs_mbedtls_ecdh_gen_public error - pufs_mbedtls_get_ecname failed\n ");
        goto cleanup;
    }

    //generate private key and save private key slot in d ------

    //clear key slot
    //check private key slot status
    key_status = ka_regs->pk[pk_idx];

    if ((key_status & KEY_VALID_BITMASK) ==  KEY_VALID_FLAG )
    {

        PUFS_LOG_DEBUG("pufs_mbedtls_ecdh_gen_public private key slot :%d not null, clear key slot\n", pk_idx);
        status = pufs_clear_key(PRKEY, priv_key_slot, 256);
        if (status != SUCCESS)
        {
            PUFS_LOG_ERR("pufs_mbedtls_ecdh_gen_public pufs_clear_key failed\n");
            ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
            goto cleanup;
        }
    }

    status = pufs_ecp_set_curve_byname(ec_name);
    if (status != SUCCESS)
    {
        PUFS_LOG_ERR("pufs_mbedtls_ecdh_gen_public error - set curve failed status :%d\n", status);
        ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
        goto cleanup;
    }

    status = pufs_ecp_gen_eprk(priv_key_slot);

    if (status != SUCCESS)
    {
        PUFS_LOG_ERR("pufs_mbedtls_ecdh_gen_public error - pufs_ecp_gen_eprk failed\n");
        ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
        goto cleanup;
    }

    //Save key slot in d
    size = sizeof(pufs_ka_slot_t);
    memcpy(buf, &priv_key_slot, size);
    mbedtls_mpi_read_binary( d, buf, size) ;

    //Generate the public key
    status = pufs_ecp_gen_puk(&pub_key, PRKEY, priv_key_slot);
    if (status != SUCCESS)
    {
        ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
        goto cleanup;
    }

    //Read public key - x, y
    ret = mbedtls_mpi_read_binary( &(Q->X), pub_key.x, pub_key.qlen );
    if (ret != 0 )
    {
        goto cleanup;
    }

    ret = mbedtls_mpi_read_binary( &(Q->Y), pub_key.y, pub_key.qlen );
    if (ret != 0 )
    {
        goto cleanup;
    }

    //Fill Z to 1. refer to ecp_type ECP_TYPE_SHORT_WEIERSTRASS (epc.c: 1711)
    //ecp_mul_comb_core (epc.c:1334)
    //For mbedtls_ecp_tls_write_point() to write public key in client key exchange
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &(Q->Z), 1 ) );


cleanup:
    if (ret != 0)
    {
        PUFS_LOG_ERR("pufs_mbedtls_ecdh_gen_public failed : ret:0x%d, status:%d\n", ret, status);
    }

    return ret;

}
#endif /* MBEDTLS_ECDH_GEN_PUBLIC_ALT */

#if defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
/*
 * Compute shared secret (SEC1 3.3.1)
 */
int pufs_mbedtls_ecdh_compute_shared( mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                      const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                      int (*f_rng)(void *, unsigned char *, size_t),
                                      void *p_rng )
{

    pufs_status_t status = SUCCESS;
    pufs_ec_name_t ec_name = N_ECNAME_T;
    uint8_t buf[MBEDTLS_MPI_MAX_SIZE];
    uint8_t shared_key[QLEN_MAX];
    pufs_ka_slot_t priv_key_slot;
    pufs_ec_point_st pub_key;
    size_t size = 0;
    int ret = 0;

    PUFS_MBEDTLS_UNUSED(f_rng);
    PUFS_MBEDTLS_UNUSED(p_rng);


    memset(shared_key, 0xEE, sizeof(shared_key));

    PUFS_LOG_FUNC("pufs_mbedtls_ecdh_compute_shared \n");

    ret = pufs_mbedtls_get_ecname(grp, &ec_name);
    if (ret != 0)
    {
        PUFS_LOG_ERR("pufs_mbedtls_ecdh_compute_shared - get ecname failed \n");
        goto cleanup;
    }


    //Read private key

    size = mbedtls_mpi_size( d );

    if (size != sizeof(pufs_ka_slot_t))
    {
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
        goto cleanup;
    }


    mbedtls_mpi_write_binary(d, buf, size);

    memcpy(&priv_key_slot, buf, size);

    //printf("priv_key_slot:%d\n", priv_key_slot);

    /*
     * Make sure Q is a valid pubkey before using it
     */
    MBEDTLS_MPI_CHK( mbedtls_ecp_check_pubkey( grp, Q ) );

    pub_key.qlen = ecc_param[ec_name].len;

    //Read peer's pubkey
    mbedtls_mpi_write_binary(&(Q->X), pub_key.x, pub_key.qlen);
    mbedtls_mpi_write_binary(&(Q->Y), pub_key.y, pub_key.qlen);

    //Generate shared key
    status = pufs_ecp_set_curve_byname(ec_name);

    if (status != SUCCESS)
    {
        PUFS_LOG_ERR("pufs_mbedtls_ecdh_compute_shared error - pufs_ecp_set_curve_byname failed status:%d\n", status);
        ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
        goto cleanup;
    }


    status = pufs_ecp_ecccdh_2e(pub_key, priv_key_slot, shared_key);

    if (status != SUCCESS)
    {

        PUFS_LOG_ERR("pufs_mbedtls_ecdh_compute_shared error - pufs_ecp_ecccdh_2e failed status:%d\n", status);
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    mbedtls_mpi_read_binary( z, shared_key, ecc_param[ec_name].len);

cleanup:
    if (ret != 0)
    {
        PUFS_LOG_ERR("pufs_mbedtls_ecdh_compute_shared failed : ret:0x%d, status:%d\n", ret, status);
    }

    return ( ret );
}


#endif /* MBEDTLS_ECDH_COMPUTE_SHARED_ALT */

#endif /* PUFS_MBEDTLS_ECDH_C */
