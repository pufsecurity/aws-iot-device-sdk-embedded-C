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
 *@file        pufs_util_pem.c
 *
 *@brief       pufs_util pem related function
 *             Original source code is from
 *             1. mbedtls/program/key_app_writers.c
 *             2. mebedtls/library/pkwrite.c
 *
 *@copyright   2023-2024 PUFsecurity
 *
 ***************************************************************************************/

#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>  //malloc, free calloc


#include "mbedtls/asn1write.h"
#include "mbedtls/base64.h"
#include "pufs_util_pem.h"
#include "mbedtls/oid.h"


#include "pufs_util_pem.h"



#define mbedtls_calloc    calloc
#define mbedtls_free       free

//From mbedtls/ecp.h
/*
 * Point formats, from RFC 4492's enum ECPointFormat
 */
#define MBEDTLS_ECP_PF_UNCOMPRESSED    0   /**< Uncompressed point format. */
#define MBEDTLS_ECP_PF_COMPRESSED      1   /**< Compressed point format. */

/*
 * ECP error codes
 */
#define MBEDTLS_ERR_ECP_BAD_INPUT_DATA                    -0x4F80  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL                  -0x4F00  /**< The buffer is too small to write to. */
#define MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE               -0x4E80  /**< The requested feature is not available, for example, the requested curve is not supported. */
#define MBEDTLS_ERR_ECP_VERIFY_FAILED                     -0x4E00  /**< The signature is not valid. */
#define MBEDTLS_ERR_ECP_ALLOC_FAILED                      -0x4D80  /**< Memory allocation failed. */
#define MBEDTLS_ERR_ECP_RANDOM_FAILED                     -0x4D00  /**< Generation of random value, such as ephemeral key, failed. */
#define MBEDTLS_ERR_ECP_INVALID_KEY                       -0x4C80  /**< Invalid private or public key. */
#define MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH                  -0x4C00  /**< The buffer contains a valid signature followed by more data. */
#define MBEDTLS_ERR_ECP_HW_ACCEL_FAILED                   -0x4B80  /**< The ECP hardware accelerator failed. */

//From mbedtls/pk.h
#define MBEDTLS_ERR_PK_ALLOC_FAILED        -0x3F80  /**< Memory allocation failed. */
#define MBEDTLS_ERR_PK_TYPE_MISMATCH       -0x3F00  /**< Type mismatch, eg attempt to encrypt with an ECDSA key */
#define MBEDTLS_ERR_PK_BAD_INPUT_DATA      -0x3E80  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_PK_FILE_IO_ERROR       -0x3E00  /**< Read/write of file failed. */
#define MBEDTLS_ERR_PK_KEY_INVALID_VERSION -0x3D80  /**< Unsupported key version */
#define MBEDTLS_ERR_PK_KEY_INVALID_FORMAT  -0x3D00  /**< Invalid key tag or value. */
#define MBEDTLS_ERR_PK_UNKNOWN_PK_ALG      -0x3C80  /**< Key algorithm is unsupported (only RSA and EC are supported). */
#define MBEDTLS_ERR_PK_PASSWORD_REQUIRED   -0x3C00  /**< Private key password can't be empty. */
#define MBEDTLS_ERR_PK_PASSWORD_MISMATCH   -0x3B80  /**< Given private key password does not allow for correct decryption. */
#define MBEDTLS_ERR_PK_INVALID_PUBKEY      -0x3B00  /**< The pubkey tag or value is invalid (only RSA and EC are supported). */
#define MBEDTLS_ERR_PK_INVALID_ALG         -0x3A80  /**< The algorithm tag or value is invalid. */
#define MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE -0x3A00  /**< Elliptic curve is unsupported (only NIST curves are supported). */
#define MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE -0x3980  /**< Unavailable feature, e.g. RSA disabled for RSA key. */
#define MBEDTLS_ERR_PK_SIG_LEN_MISMATCH    -0x3900  /**< The buffer contains a valid signature followed by more data. */
#define MBEDTLS_ERR_PK_HW_ACCEL_FAILED     -0x3880  /**< PK hardware accelerator failed. */


//From mbedtls/pem.h
/**
 * \name PEM Error codes
 * These error codes are returned in case of errors reading the
 * PEM data.
 * \{
 */
#define MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT          -0x1080  /**< No PEM header or footer found. */
#define MBEDTLS_ERR_PEM_INVALID_DATA                      -0x1100  /**< PEM string is not as expected. */
#define MBEDTLS_ERR_PEM_ALLOC_FAILED                      -0x1180  /**< Failed to allocate memory. */
#define MBEDTLS_ERR_PEM_INVALID_ENC_IV                    -0x1200  /**< RSA IV is not in hex-format. */
#define MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG                   -0x1280  /**< Unsupported key encryption algorithm. */
#define MBEDTLS_ERR_PEM_PASSWORD_REQUIRED                 -0x1300  /**< Private key password can't be empty. */
#define MBEDTLS_ERR_PEM_PASSWORD_MISMATCH                 -0x1380  /**< Given private key password does not allow for correct decryption. */
#define MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE               -0x1400  /**< Unavailable feature, e.g. hashing/encryption combination. */
#define MBEDTLS_ERR_PEM_BAD_INPUT_DATA                    -0x1480  /**< Bad input parameters to function. */
/* \} name */


//Below from bignum.h
#define MBEDTLS_MPI_CHK(f) do { if( ( ret = f ) != 0 ) goto cleanup; } while( 0 )


/*
 * Some other constants from RFC 4492
 */
#define MBEDTLS_ECP_TLS_NAMED_CURVE    3   /**< The named_curve of ECCurveType. */



#define PEM_BEGIN_PUBLIC_KEY    "-----BEGIN PUBLIC KEY-----\n"
#define PEM_END_PUBLIC_KEY      "-----END PUBLIC KEY-----\n"

#define PEM_BEGIN_PRIVATE_KEY_RSA   "-----BEGIN RSA PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY_RSA     "-----END RSA PRIVATE KEY-----\n"
#define PEM_BEGIN_PRIVATE_KEY_EC    "-----BEGIN EC PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY_EC      "-----END EC PRIVATE KEY-----\n"


#if !defined(MBEDTLS_ECP_MAX_BITS)
/**
 * The maximum size of the groups, that is, of \c N and \c P.
 */
#define MBEDTLS_ECP_MAX_BITS     521   /**< The maximum size of groups, in bits. */
#endif

#define MBEDTLS_ECP_MAX_BYTES    ( ( MBEDTLS_ECP_MAX_BITS + 7 ) / 8 )
#define MBEDTLS_ECP_MAX_PT_LEN   ( 2 * MBEDTLS_ECP_MAX_BYTES + 1 )

#define MBEDTLS_MPI_MAX_SIZE                              1024     /**< Maximum number of bytes for usable MPIs. */
#define MBEDTLS_MPI_MAX_BITS                              ( 8 * MBEDTLS_MPI_MAX_SIZE )    /**< Maximum number of bits for usable MPIs. */


/*
 * Max sizes of key per types. Shown as tag + len (+ content).
 */

#if defined(MBEDTLS_RSA_C)
/*
 * RSA public keys:
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {          1 + 3
 *       algorithm            AlgorithmIdentifier,  1 + 1 (sequence)
 *                                                + 1 + 1 + 9 (rsa oid)
 *                                                + 1 + 1 (params null)
 *       subjectPublicKey     BIT STRING }          1 + 3 + (1 + below)
 *  RSAPublicKey ::= SEQUENCE {                     1 + 3
 *      modulus           INTEGER,  -- n            1 + 3 + MPI_MAX + 1
 *      publicExponent    INTEGER   -- e            1 + 3 + MPI_MAX + 1
 *  }
 */
#define RSA_PUB_DER_MAX_BYTES   38 + 2 * MBEDTLS_MPI_MAX_SIZE

/*
 * RSA private keys:
 *  RSAPrivateKey ::= SEQUENCE {                    1 + 3
 *      version           Version,                  1 + 1 + 1
 *      modulus           INTEGER,                  1 + 3 + MPI_MAX + 1
 *      publicExponent    INTEGER,                  1 + 3 + MPI_MAX + 1
 *      privateExponent   INTEGER,                  1 + 3 + MPI_MAX + 1
 *      prime1            INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      prime2            INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      exponent1         INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      exponent2         INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      coefficient       INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      otherPrimeInfos   OtherPrimeInfos OPTIONAL  0 (not supported)
 *  }
 */
#define MPI_MAX_SIZE_2          MBEDTLS_MPI_MAX_SIZE / 2 + \
                                MBEDTLS_MPI_MAX_SIZE % 2
#define RSA_PRV_DER_MAX_BYTES   47 + 3 * MBEDTLS_MPI_MAX_SIZE \
                                   + 5 * MPI_MAX_SIZE_2

#else /* MBEDTLS_RSA_C */

#define RSA_PUB_DER_MAX_BYTES   0
#define RSA_PRV_DER_MAX_BYTES   0

#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_ECP_C)
/*
 * EC public keys:
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {      1 + 2
 *    algorithm         AlgorithmIdentifier,    1 + 1 (sequence)
 *                                            + 1 + 1 + 7 (ec oid)
 *                                            + 1 + 1 + 9 (namedCurve oid)
 *    subjectPublicKey  BIT STRING              1 + 2 + 1               [1]
 *                                            + 1 (point format)        [1]
 *                                            + 2 * ECP_MAX (coords)    [1]
 *  }
 */
#define ECP_PUB_DER_MAX_BYTES   30 + 2 * MBEDTLS_ECP_MAX_BYTES

/*
 * EC private keys:
 * ECPrivateKey ::= SEQUENCE {                  1 + 2
 *      version        INTEGER ,                1 + 1 + 1
 *      privateKey     OCTET STRING,            1 + 1 + ECP_MAX
 *      parameters [0] ECParameters OPTIONAL,   1 + 1 + (1 + 1 + 9)
 *      publicKey  [1] BIT STRING OPTIONAL      1 + 2 + [1] above
 *    }
 */
#define ECP_PRV_DER_MAX_BYTES   29 + 3 * MBEDTLS_ECP_MAX_BYTES

#else /* MBEDTLS_ECP_C */

#define ECP_PUB_DER_MAX_BYTES   0
#define ECP_PRV_DER_MAX_BYTES   0

#endif /* MBEDTLS_ECP_C */

#define PUB_DER_MAX_BYTES   RSA_PUB_DER_MAX_BYTES > ECP_PUB_DER_MAX_BYTES ? \
                            RSA_PUB_DER_MAX_BYTES : ECP_PUB_DER_MAX_BYTES
#define PRV_DER_MAX_BYTES   RSA_PRV_DER_MAX_BYTES > ECP_PRV_DER_MAX_BYTES ? \
                            RSA_PRV_DER_MAX_BYTES : ECP_PRV_DER_MAX_BYTES


/*****************************************************************************/
/**
 * @fn              pufs_util_ecp_point_write_binary
 * @brief           This function exports a point into unsigned binary data.
 *
 * @param kpub      The point to export.
 * @param format    The point format. Should be an \c MBEDTLS_ECP_PF_XXX macro.
 * @param olen      The length of the output.
 * @param buf       The output buffer.
 * @param buflen    The length of the output buffer.
 *
 * @return          \c 0 on success.
 * @return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA
 *                  or #MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL on failure.
 *
 ****************************************************************************/

int pufs_util_ecp_point_write_binary( pufs_ec_point_st *kpub,
                                      int format, size_t *olen,
                                      unsigned char *buf, size_t buflen )
{
    int ret = 0;
    size_t plen;

    if ( format != MBEDTLS_ECP_PF_UNCOMPRESSED &&
         format != MBEDTLS_ECP_PF_COMPRESSED )
        return ( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );


    plen = kpub->qlen;

    if (buf != NULL )
    {
        memset(buf, 0, buflen);
    }
    else
    {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if ( format == MBEDTLS_ECP_PF_UNCOMPRESSED )
    {
        *olen = 2 * plen + 1;

        if ( buflen < *olen )
            return ( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

        buf[0] = 0x04;
        memcpy(buf + 1, kpub->x, plen);
        memcpy(buf + 1 + plen, kpub->y, plen);
    }
    else if ( format == MBEDTLS_ECP_PF_COMPRESSED )
    {
        *olen = plen + 1;

        if ( buflen < *olen )
            return ( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

        //to check
        buf[0] = 0x02 + kpub->y[0];
        memcpy(buf + 1, kpub->x, plen);
    }

    return ( ret );
}


/*
 * Note : EC public key is an EC point
 */

/*****************************************************************************/
/**
 * @fn              pufs_util_write_ec_pubkey
 * @brief           Write a subjectPublicKey to ASN.1 data
 *                  Note: function works backwards in data buffer
 *
 * @param p         reference to current position pointer
 * @param start     start of the buffer (for bounds-checking)
 * @param kpub      public key to write away
 *
 * @return          the length written or a negative error code
 *
 ****************************************************************************/

static int pufs_util_write_ec_pubkey( unsigned char **p, unsigned char *start,
                                      pufs_ec_point_st *kpub )
{
    int ret;
    size_t len = 0;
    unsigned char buf[MBEDTLS_ECP_MAX_PT_LEN];

    if ( ( ret = pufs_util_ecp_point_write_binary( kpub,
                                                   MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                   &len, buf, sizeof( buf ) ) ) != 0 )
    {
        return ( ret );
    }

    if ( *p < start || (size_t)( *p - start ) < len )
        return ( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    *p -= len;
    memcpy( *p, buf, len );

    return ( (int) len );
}



/*
 * ECParameters ::= CHOICE {
 *   namedCurve         OBJECT IDENTIFIER
 * }
 */

/*****************************************************************************/
/**
 * @fn              pk_write_ec_param
 * @brief           Write EC Parameters (oid of nambedCurve)
 *
 * @param p         reference to current position pointer
 * @param start     start of the buffer (for bounds-checking)
 * @param gid       ecp group id
 *
 * @return          the length written or a negative error code
 *
 ****************************************************************************/

static int pk_write_ec_param( unsigned char **p, unsigned char *start,
                              mbedtls_ecp_group_id gid )
{
    int ret;
    size_t len = 0;
    const char *oid;
    size_t oid_len;

    //Fixme : grp is hard-coded
    if ( ( ret = mbedtls_oid_get_oid_by_ec_grp( gid,
                                                &oid, &oid_len ) ) != 0 )
    {
        printf("mbedtls_oid_get_oid_by_ec_grp  1 gid:%d oid_len:%zd ret:%d \n", gid, oid_len, ret);
        return ( ret );
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_oid( p, start, oid, oid_len ) );

    return ( (int) len );
}

/*****************************************************************************/
/**
 * @fn              pufs_util_write_ec_pubkey_der
 * @brief           Write a public key to a SubjectPublicKeyInfo DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * @param kpub      public key to write away
 * @param buf       buffer to write to
 * @param size      size of the buffer
 * @param gid       ecp group id
 *
 * @return          length of data written if successful, or a specific
 *                  error code*
 ****************************************************************************/

int pufs_util_write_ec_pubkey_der( pufs_ec_point_st *kpub, unsigned char *buf, size_t size,
                                   mbedtls_ecp_group_id gid)
{
    int ret;
    unsigned char *c;
    size_t len = 0, par_len = 0, oid_len;
    const char *oid;

    c = buf + size;

    MBEDTLS_ASN1_CHK_ADD( len, pufs_util_write_ec_pubkey( &c, buf, kpub ) );

    if ( c - buf < 1 )
        return ( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    /*
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm            AlgorithmIdentifier,
     *       subjectPublicKey     BIT STRING }
     */
    *--c = 0;
    len += 1;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_BIT_STRING ) );

    if ( ( ret = mbedtls_oid_get_oid_by_pk_alg( MBEDTLS_PK_ECKEY,
                                                &oid, &oid_len ) ) != 0 )
    {
        PUFS_LOG_ERR("mbedtls_oid_get_oid_by_pk_alg failed :%d oid_len:%zd\n", ret, oid_len);
        return ( ret );
    }

    MBEDTLS_ASN1_CHK_ADD( par_len, pk_write_ec_param( &c, buf, gid ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( &c, buf, oid, oid_len,
                                                                        par_len ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                       MBEDTLS_ASN1_SEQUENCE ) );

    return ( (int) len );
}


/*****************************************************************************/
/**
 * @fn              mbedtls_pem_write_buffer
 * @brief           Write a buffer of PEM information from a DER encoded
 *                  buffer.
 *
 * @param header    header string to write
 * @param footer    footer string to write
 * @param der_data  DER data to write
 * @param der_len   length of the DER data
 * @param buf       buffer to write to
 * @param buf_len   length of output buffer
 * @param olen      total length written / required (if buf_len is not enough)
 *
 * @return          0 on success, or a specific PEM or BASE64 error code. On
 *                  MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL olen is the required
 *                  size.
 *
 ****************************************************************************/

int mbedtls_pem_write_buffer( const char *header, const char *footer,
                              const unsigned char *der_data, size_t der_len,
                              unsigned char *buf, size_t buf_len, size_t *olen )
{
    int ret;
    unsigned char *encode_buf = NULL, *c, *p = buf;
    size_t len = 0, use_len, add_len = 0;

    mbedtls_base64_encode( NULL, 0, &use_len, der_data, der_len );
    add_len = strlen( header ) + strlen( footer ) + ( use_len / 64 ) + 1;

    if ( use_len + add_len > buf_len )
    {
        *olen = use_len + add_len;
        return ( MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL );
    }

    if ( use_len != 0 &&
         ( ( encode_buf = mbedtls_calloc( 1, use_len ) ) == NULL ) )
        return ( MBEDTLS_ERR_PEM_ALLOC_FAILED );

    if ( ( ret = mbedtls_base64_encode( encode_buf, use_len, &use_len, der_data,
                                        der_len ) ) != 0 )
    {
        mbedtls_free( encode_buf );
        return ( ret );
    }

    memcpy( p, header, strlen( header ) );
    p += strlen( header );
    c = encode_buf;

    while ( use_len )
    {
        len = ( use_len > 64 ) ? 64 : use_len;
        memcpy( p, c, len );
        use_len -= len;
        p += len;
        c += len;
        *p++ = '\n';
    }

    memcpy( p, footer, strlen( footer ) );
    p += strlen( footer );

    *p++ = '\0';
    *olen = p - buf;

    mbedtls_free( encode_buf );
    return ( 0 );
}


/*****************************************************************************/
/**
 * @fn              pufs_util_write_ecdsa_pubkey_pem
 * @brief           Write a ecdsa public key to a PKCS#1 or SEC1 PEM string
 *
 * @param key       public key to write away
 * @param buf       buffer to write to
 * @param size      size of the buffer
 *
 * @return          0 if successful, or a specific error code
 *
 ****************************************************************************/

int pufs_util_write_ecdsa_pubkey_pem( pufs_ec_point_st *key, unsigned char *buf, size_t size, mbedtls_ecp_group_id gid)
{
    int ret;
    unsigned char output_buf[PUB_DER_MAX_BYTES];
    size_t olen = 0;

    if ( ( ret = pufs_util_write_ec_pubkey_der( key, output_buf,
                                                sizeof(output_buf), gid ) ) < 0 )
    {
        PUFS_LOG_ERR("pufs_util_write_ec_pubkey_der failed, ret:%d\n", ret);
        return ( ret );
    }


    if ( ( ret = mbedtls_pem_write_buffer( PEM_BEGIN_PUBLIC_KEY, PEM_END_PUBLIC_KEY,
                                           output_buf + sizeof(output_buf) - ret,
                                           ret, buf, size, &olen ) ) != 0 )
    {
        PUFS_LOG_ERR("mbedtls_pem_write_buffer failed, ret:%d olen:%zd\n", ret, olen);


        return ( ret );
    }

    return ( 0 );
}
