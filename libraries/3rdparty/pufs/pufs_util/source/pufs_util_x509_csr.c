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
 *@file        pufs_util_x509_csr.c
 *
 *@brief       pufs_util to generate certificate request
 *
 *             Mbedtls codes (V2.12.0) referenced :
 *             1. mebedtls/programs/x509/cert_req.c
 *             2. mebedtls/programs/library/pkparse.c
 *             ˇ. mebedtls/programs/library/x509write_csr.c
 *
 *@copyright   2023-2024 PUFsecurity
 *
 ***************************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


#include "mbedtls/x509_csr.h"

#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "pufs_util_common.h"
#include "pufs_util_sec.h"
#include "pufs_util_pem.h" // for mbedtls_pem_write_buffer


#define mbedtls_printf          printf
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE


extern const mbedtls_pk_info_t mbedtls_pufs_eckey_info;


int pufs_util_mbedtls_x509write_csr_der( mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size,
                                         int (*f_rng)(void *, unsigned char *, size_t),
                                         void *p_rng )
{
    int ret;
    const char *sig_oid;
    size_t sig_oid_len = 0;
    unsigned char *c, *c2;
    unsigned char hash[64];
    unsigned char sig[MBEDTLS_MPI_MAX_SIZE];
    unsigned char tmp_buf[2048];
    size_t pub_len = 0, sig_and_oid_len = 0, sig_len;
    size_t len = 0;
    mbedtls_pk_type_t pk_alg;

    /*
     * Prepare data to be signed in tmp_buf
     */
    c = tmp_buf + sizeof( tmp_buf );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_x509_write_extensions( &c, tmp_buf, ctx->extensions ) );

    if ( len )
    {
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                           MBEDTLS_ASN1_SEQUENCE ) );

        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                           MBEDTLS_ASN1_SET ) );

        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_oid( &c, tmp_buf, MBEDTLS_OID_PKCS9_CSR_EXT_REQ,
                                                           MBEDTLS_OID_SIZE( MBEDTLS_OID_PKCS9_CSR_EXT_REQ ) ) );

        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                           MBEDTLS_ASN1_SEQUENCE ) );
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                       MBEDTLS_ASN1_CONTEXT_SPECIFIC ) );

    MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_pk_write_pubkey_der( ctx->key,
                                                                tmp_buf, c - tmp_buf ) );
    c -= pub_len;
    len += pub_len;

    /*
     *  Subject  ::=  Name
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_x509_write_names( &c, tmp_buf, ctx->subject ) );

    /*
     *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( &c, tmp_buf, 0 ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                       MBEDTLS_ASN1_SEQUENCE ) );

    /*
     * Prepare signature
     */

    rt_status_t rt = PUFS_SUCCESS;
    rt = pufs_util_sec_sha256(hash, c, len);

    if (rt != PUFS_SUCCESS)
    {
        printf("SHA failed rt:%d \n", rt);
    }

    if ( ( ret = mbedtls_pk_sign( ctx->key, ctx->md_alg, hash, 0, sig, &sig_len,
                                  f_rng, p_rng ) ) != 0 )
    {
        PUFS_LOG_ERR("mbedtls_pk_sign failed ret: -0x%x\n", -ret);
        return ( ret );
    }


    if ( mbedtls_pk_can_do( ctx->key, MBEDTLS_PK_RSA ) )
        pk_alg = MBEDTLS_PK_RSA;
    else if ( mbedtls_pk_can_do( ctx->key, MBEDTLS_PK_ECDSA ) )
        pk_alg = MBEDTLS_PK_ECDSA;
    else
        return ( MBEDTLS_ERR_X509_INVALID_ALG );

    if ( ( ret = mbedtls_oid_get_oid_by_sig_alg( pk_alg, ctx->md_alg,
                                                 &sig_oid, &sig_oid_len ) ) != 0 )
    {
        PUFS_LOG_ERR("mbedtls_oid_get_oid_by_sig_alg failed ret: -0x%x\n", -ret);
        return ( ret );
    }

    /*
     * Write data to output buffer
     */
    c2 = buf + size;
    MBEDTLS_ASN1_CHK_ADD( sig_and_oid_len, mbedtls_x509_write_sig( &c2, buf,
                                                                   sig_oid, sig_oid_len, sig, sig_len ) );

    if ( len > (size_t)( c2 - buf ) )
        return ( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    c2 -= len;
    memcpy( c2, c, len );

    len += sig_and_oid_len;
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c2, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c2, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                       MBEDTLS_ASN1_SEQUENCE ) );

    return ( (int) len );
}


#define PEM_BEGIN_CSR           "-----BEGIN CERTIFICATE REQUEST-----\n"
#define PEM_END_CSR             "-----END CERTIFICATE REQUEST-----\n"

int pufs_util_mbedtls_x509write_csr_pem( mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size,
                                         int (*f_rng)(void *, unsigned char *, size_t),
                                         void *p_rng )
{
    int ret;
    unsigned char output_buf[4096];
    size_t olen = 0;

    if ( ( ret = pufs_util_mbedtls_x509write_csr_der( ctx, output_buf, sizeof(output_buf),
                                                      f_rng, p_rng ) ) < 0 )
    {
        PUFS_LOG_ERR("pufs_util_mbedtls_x509write_csr_der failed ret:-0x%x\n", -ret);
        return ( ret );
    }

    if ( ( ret = mbedtls_pem_write_buffer( PEM_BEGIN_CSR, PEM_END_CSR,
                                           output_buf + sizeof(output_buf) - ret,
                                           ret, buf, size, &olen ) ) != 0 )
    {
        PUFS_LOG_ERR("mbedtls_pem_write_buffer failed ret:-0x%x\n", -ret);

        return ( ret );
    }

    return ( 0 );
}


int pufs_util_write_certificate_request( mbedtls_x509write_csr *req, const char *output_file,
                                         int (*f_rng)(void *, unsigned char *, size_t),
                                         void *p_rng )
{
    int ret;
    FILE *f;
    unsigned char output_buf[4096];
    size_t len = 0;

    memset( output_buf, 0, 4096 );
    if ( ( ret = pufs_util_mbedtls_x509write_csr_pem( req, output_buf, 4096, f_rng, p_rng ) ) < 0 )
        return ( ret );

    len = strlen( (char *) output_buf );

    if ( ( f = fopen( output_file, "w" ) ) == NULL )
        return ( -1 );

    if ( fwrite( output_buf, 1, len, f ) != len )
    {
        fclose( f );
        return ( -1 );
    }

    fclose( f );

    return ( 0 );
}


/*
 * Parse a private key
 */
int pufs_util_mbedtls_ec_pk_set( mbedtls_pk_context *pk,
                                 pufs_ka_slot_t priv_key_slot,
                                 pufs_ec_point_st *pub_key,
                                 mbedtls_ecp_group_id gid)
{
    int ret;
    const mbedtls_pk_info_t *pk_info;
    mbedtls_ecp_keypair *ec_key_pair = NULL;

    pk_info = &mbedtls_pufs_eckey_info;

    ret = mbedtls_pk_setup( pk, pk_info );

    ec_key_pair = (mbedtls_ecp_keypair *)(pk->pk_ctx);

    if ( ( ret = mbedtls_ecp_group_load( &(ec_key_pair->grp), gid ) ) != 0 )
    {
        PUFS_LOG_ERR("load group failed ret: -0x%x\n", ret);
        return ( ret );
    }

    ret = mbedtls_mpi_read_binary(&(ec_key_pair->Q.X), pub_key->x, pub_key->qlen);
    if (ret != 0)
    {
        PUFS_LOG_ERR("Read x failed err:0x%x\n", ret);
        return ret;
    }

    ret = mbedtls_mpi_read_binary(&(ec_key_pair->Q.Y), pub_key->y, pub_key->qlen);
    if (ret != 0)
    {
        PUFS_LOG_ERR("Read y failed err:- 0x%x\n", -ret);
        return ret;
    }

    //set Z
    ret = mbedtls_mpi_lset( &ec_key_pair->Q.Z, 1 );

    if (ret != 0)
    {
        PUFS_LOG_ERR("set Z value = 1 failed err:- 0x%x\n", -ret);
        return ret;
    }

    //set private key d
    ret = mbedtls_mpi_read_binary(&(ec_key_pair->d), (const unsigned char *)(&priv_key_slot), 4 );
    if (ret != 0)
    {
        PUFS_LOG_ERR("Read d failed err:- 0x%x\n", -ret);
        return ret;
    }
    return 0;
}



/**
 * @fn    pufs_util_write_x509_ecdsa_key_csr
 * @brief Write ecdsa key csr
 *
 * @param[in]  pub_key         public key
 * @param[in]  priv_key_slot   private key slot
 *                             (value : PRK_1 - PRK_3)
 * @param[in]  gid             group ip (current MBEDTLS_ECP_DP_SECP256R1 )
 * @param[in]  file_name       file name
 * @param[in]  common_name     string of certificate common name
 *
 */

int pufs_util_write_x509_ecdsa_key_csr( pufs_ec_point_st *pub_key, pufs_ka_slot_t priv_key_slot,
                                        mbedtls_ecp_group_id gid, char *file_name, char *common_name)

{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_pk_context key;
    char buf[1024];
    mbedtls_x509write_csr req;

    //const char subject_name[] = "C=TW,ST=TW,L=HSINCHU,O=PUFsecruity,OU=RD2,CN=pufsecurity.com";
    //const char subject_name[] = "C=TW,ST=TW,L=HSINCHU,O=PUFsecruity,OU=RD2,CN=c-test-iot-device-puf-fpga";
    //const char subject_name[] = "C=TW,ST=TW,L=HSINCHU,O=PUFsecruity,OU=RD2,CN=pufs_4768418ee32618c6ddce00bbcb67f896c3fc0087639219c7ca3240949be47a37";
    const char subject_name_base[] = "C=TW,ST=TW,L=HSINCHU,O=PUFsecruity,OU=RD2,";
    const char common_name_default[] = "CN=c-test-iot-device-puf-fpga";
    char *p_subject_name = NULL;
    char *p_tmp = NULL;
    unsigned char key_usage = 0;

    //todo : common_name check, calloc check
    if (common_name == NULL)
    {
        // +1: string end
        p_subject_name = calloc((strlen(subject_name_base) + strlen(common_name_default) + 1),
                                sizeof(char));
        p_tmp = p_subject_name;
        memcpy(p_tmp, subject_name_base, strlen(subject_name_base));
        p_tmp += strlen(subject_name_base);
        memcpy(p_tmp, common_name_default, strlen(common_name_default));
    }
    else
    {
        // +1 : string end, +3: "CN="
        p_subject_name = calloc((strlen(subject_name_base) + strlen(common_name) + 1 + 3),
                                sizeof(char));

        p_tmp = p_subject_name;
        memcpy(p_tmp, subject_name_base, strlen(subject_name_base));
        p_tmp += strlen(subject_name_base);
        memcpy(p_tmp, "CN=", 3);
        p_tmp += 3;
        memcpy(p_tmp, common_name, strlen(common_name));
        printf("str cmn len:%zd\n", strlen(common_name));
    }

    PUFS_LOG_INFO("subject name:%s\n", p_subject_name);

    /*
     * Set to sane values
     */
    mbedtls_x509write_csr_init( &req );
    mbedtls_x509write_csr_set_md_alg( &req, MBEDTLS_MD_SHA256 );
    mbedtls_pk_init( &key );
    memset( buf, 0, sizeof( buf ) );

    //Key Usage
    key_usage = MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
    if (key_usage)
    {
        mbedtls_x509write_csr_set_key_usage( &req, key_usage );
    }

    /*
     * 1.0. Check the subject name for validity
     */

    mbedtls_printf( "  . Checking subject name ..." );
    fflush( stdout );


    if (strlen(p_subject_name) > 0)
    {
        if ( ( ret = mbedtls_x509write_csr_set_subject_name( &req, (const char *) p_subject_name ) ) != 0 )
        {
            mbedtls_printf( " failed\n  !  mbedtls_x509write_csr_set_subject_name returned -0x%x", -ret );
            goto exit;
        }
    }

    mbedtls_printf( " ok\n" );

    /*
     * 1.1. Load the key
     */
    mbedtls_printf( "  . Loading the private key ..." );
    fflush( stdout );

    ret = pufs_util_mbedtls_ec_pk_set(&key, priv_key_slot, pub_key, MBEDTLS_ECP_DP_SECP256R1 );

    if ( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_pk_parse_keyfile returned -0x%x", -ret );
        goto exit;
    }

    mbedtls_x509write_csr_set_key( &req, &key );

    mbedtls_printf( " ok\n" );

    /*
     * 1.2. Writing the request
     */
    mbedtls_printf( "  . Writing the certificate request ..." );
    fflush( stdout );

    if ( ( ret = pufs_util_write_certificate_request( &req, file_name,
                                                      NULL, NULL ) ) != 0 )
    {
        mbedtls_printf( " failed\n  !  write_certifcate_request - 0x%x", -ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

    if ( exit_code != MBEDTLS_EXIT_SUCCESS )
    {
#ifdef MBEDTLS_ERROR_C
        mbedtls_strerror( ret, buf, sizeof( buf ) );
        mbedtls_printf( " - %s\n", buf );
#else
        mbedtls_printf("\n");
#endif
    }
    mbedtls_x509write_csr_free( &req );
    mbedtls_pk_free( &key );

    return ( exit_code );
}
