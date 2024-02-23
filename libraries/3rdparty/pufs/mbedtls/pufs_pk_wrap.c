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
 *@file        pufs_pk_wrap.c
 *
 *@brief       pufsecruity "Public Key Abstraction layer" wrraper functions for
 *             pufsecurity ec key (mbedtls_pufs_eckey_info)
 *
 *             Some source code is from
 *             1. mebedtls/library/pk_wrap.c
 *
 *@copyright   2023-2024 PUFsecurity
 *
 ***************************************************************************************/


#include <stdio.h>


#include "pufs_mbedtls_config.h"


#if defined(MBEDTLS_PK_C)
#include "mbedtls/pk_internal.h"
#include "mbedtls/asn1write.h"


#include "pufs_ka.h"

#ifdef PUFSE_HOST
#include "pufs_pkc.h"
#else
#include "pufs_common.h"
#include "pufs_ecc.h"
#include "pufs_ecp.h"
#endif
#include <stdio.h>


#include <string.h>

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif

#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#endif


#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include <limits.h>
#include <stdint.h>


#if 0
#define PRINT_FUNC() {}

#else
#define PRINT_FUNC() \
    {   \
        printf("      %s\n", __func__); \
    }
#endif


#if defined(MBEDTLS_ECP_C)
/*
 * Generic EC key
 */
static int pufs_eckey_can_do( mbedtls_pk_type_t type )
{
    PRINT_FUNC();

    return ( type == MBEDTLS_PK_ECKEY ||
             type == MBEDTLS_PK_ECKEY_DH ||
             type == MBEDTLS_PK_ECDSA );
}

static size_t pufs_eckey_get_bitlen( const void *ctx )
{
    PRINT_FUNC();

    return ( ((mbedtls_ecp_keypair *) ctx)->grp.pbits );
}

#if defined(MBEDTLS_ECDSA_C)
/* Forward declarations */
static int pufs_ecdsa_verify_wrap( void *ctx, mbedtls_md_type_t md_alg,
                                   const unsigned char *hash, size_t hash_len,
                                   const unsigned char *sig, size_t sig_len );

static int pufs_ecdsa_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                                 const unsigned char *hash, size_t hash_len,
                                 unsigned char *sig, size_t *sig_len,
                                 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );


static int pufs_eckey_verify_wrap( void *ctx, mbedtls_md_type_t md_alg,
                                   const unsigned char *hash, size_t hash_len,
                                   const unsigned char *sig, size_t sig_len )
{
    int ret;
    mbedtls_ecdsa_context ecdsa;

    PRINT_FUNC();

    mbedtls_ecdsa_init( &ecdsa );

    if ( ( ret = mbedtls_ecdsa_from_keypair( &ecdsa, ctx ) ) == 0 )
        ret = pufs_ecdsa_verify_wrap( &ecdsa, md_alg, hash, hash_len, sig, sig_len );

    mbedtls_ecdsa_free( &ecdsa );

    return ( ret );
}


/*
 * Convert a signature (given by context) to ASN.1
 */

static int pufs_ecdsa_signature_to_asn1( const mbedtls_mpi *r, const mbedtls_mpi *s,
                                         unsigned char *sig, size_t *slen )
{
    int ret;
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN];
    unsigned char *p = buf + sizeof( buf );
    size_t len = 0;

    PRINT_FUNC();

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &p, buf, s ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &p, buf, r ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &p, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &p, buf,
                                                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );


    memcpy( sig, p, len );
    *slen = len;

    return ( 0 );
}


static int pufs_eckey_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                                 const unsigned char *hash, size_t hash_len,
                                 unsigned char *sig, size_t *sig_len,
                                 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret;
    mbedtls_ecdsa_context ecdsa;

    mbedtls_ecdsa_init( &ecdsa );

    if ( ( ret = mbedtls_ecdsa_from_keypair( &ecdsa, ctx ) ) == 0 )
        ret = pufs_ecdsa_sign_wrap( &ecdsa, md_alg, hash, hash_len, sig, sig_len,
                                    f_rng, p_rng );

    mbedtls_ecdsa_free( &ecdsa );

    return ( ret );
}


#endif /* MBEDTLS_ECDSA_C */


static void *pufs_eckey_alloc_wrap( void )
{

    PRINT_FUNC();

    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_ecp_keypair ) );

    if ( ctx != NULL )
        mbedtls_ecp_keypair_init( ctx );

    return ( ctx );
}

static void pufs_eckey_free_wrap( void *ctx )
{
    PRINT_FUNC();

    mbedtls_ecp_keypair_free( (mbedtls_ecp_keypair *) ctx );
    mbedtls_free( ctx );
}


static int pufs_eckey_check_pair( const void *pub, const void *prv )
{
    PRINT_FUNC();

#if 1
    printf("To do\n");
    return 0;
#else
    return ( mbedtls_ecp_check_pub_priv( (const mbedtls_ecp_keypair *) pub,
                                         (const mbedtls_ecp_keypair *) prv ) );
#endif
}

static void pufs_eckey_debug( const void *ctx, mbedtls_pk_debug_item *items )
{
    PRINT_FUNC();

    items->type = MBEDTLS_PK_DEBUG_ECP;
    items->name = "eckey.Q";
    items->value = &( ((mbedtls_ecp_keypair *) ctx)->Q );
}


const mbedtls_pk_info_t mbedtls_pufs_eckey_info =
{
    MBEDTLS_PK_ECKEY,
    "EC",
    pufs_eckey_get_bitlen,
    pufs_eckey_can_do,
#if defined(MBEDTLS_ECDSA_C)
    pufs_eckey_verify_wrap,
    pufs_eckey_sign_wrap,
#else
    NULL,
    NULL,
#endif
    NULL,
    NULL,
    pufs_eckey_check_pair,
    pufs_eckey_alloc_wrap,
    pufs_eckey_free_wrap,
    pufs_eckey_debug,
};

#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_ECDSA_C)

static int pufs_ecdsa_verify_wrap( void *ctx, mbedtls_md_type_t md_alg,
                                   const unsigned char *hash, size_t hash_len,
                                   const unsigned char *sig, size_t sig_len )
{
    int ret;
    ((void) md_alg);

    PRINT_FUNC();

#if 1
    printf("To Do!!\n");
    return 0;
#else
    ret = mbedtls_ecdsa_read_signature( (mbedtls_ecdsa_context *) ctx,
                                        hash, hash_len, sig, sig_len );
#endif

    if ( ret == MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH )
        return ( MBEDTLS_ERR_PK_SIG_LEN_MISMATCH );

    return ( ret );
}

static int pufs_ecdsa_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                                 const unsigned char *hash, size_t hash_len,
                                 unsigned char *sig, size_t *sig_len,
                                 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret;
    pufs_status_t check = SUCCESS;
    pufs_ecdsa_sig_st pufs_ec_sig;
    pufs_dgst_st md;
    mbedtls_ecdsa_context *ec_ctx = (mbedtls_ecdsa_context *)ctx;
    uint32_t key_slot ;
    mbedtls_mpi r, s;

    PRINT_FUNC();

    mbedtls_mpi_write_binary(&(ec_ctx->d), (unsigned char *)&key_slot, 4);

    if ((md_alg != MBEDTLS_MD_SHA256) ||
        ((key_slot < PRK_0) ||
         (key_slot > PRK_2)))
    {
        printf("pufs_eckey_sign_wrap parameter error!! alg:%d, key_slot:%d\n", md_alg, key_slot);
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        return ret;
    }
    else
    {
        memset(&pufs_ec_sig, 0, sizeof(pufs_ecdsa_sig_st));
        memset(&md, 0, sizeof(pufs_dgst_st));
        md.dlen = hash_len;
        memcpy(md.dgst, hash, hash_len);
        check = pufs_ecp_ecdsa_sign_dgst(&pufs_ec_sig, md, PRKEY, key_slot, NULL);
        if (check != SUCCESS)
        {
            printf("pufs_ecp_ecdsa_sign_dgst failed, check :%d\n", check);
            ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
            return ret;

        }
        mbedtls_mpi_init( &r );
        mbedtls_mpi_init( &s );

        ret = mbedtls_mpi_read_binary( &r, (const unsigned char *)(&(pufs_ec_sig.r)), pufs_ec_sig.qlen );
        if (ret != 0)
        {
            printf("read r to mpi failed ret:-0x%x\n", -ret);
        }

        ret = mbedtls_mpi_read_binary( &s, (const unsigned char *)(&(pufs_ec_sig.s)), pufs_ec_sig.qlen );
        if (ret != 0)
        {
            printf("read r to mpi failed ret:-0x%x\n", -ret);
        }

        ret = pufs_ecdsa_signature_to_asn1( &r, &s, sig, sig_len );
        if (ret != 0)
        {
            printf("write sig to sig_buf failed ret:-0x%x\n", -ret);
        }
    }

    return ( ret );
}
#endif /* MBEDTLS_ECDSA_C */

#endif /* MBEDTLS_PK_C */
