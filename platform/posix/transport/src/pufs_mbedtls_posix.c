/***********************************************************************************
 *
 * Copyright (C) 2023-2024 PUFsecurity and/or its affiliates. All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 *
 **************************************************************************************/

/*
 * AWS IoT Device SDK for Embedded C 202211.00
 * Copyright (C) 2023 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* Standard includes. */
#include <assert.h>
#include <string.h>


/* TLS transport header. */
#include "pufs_mbedtls_posix.h"

/* MbedTLS includes. */
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/ctr_drbg.h"

#ifdef PUFS_MBEDTLS_KEY_CB_LOG
#include "mbedtls/ssl.h"
#endif


/*-----------------------------------------------------------*/

/**
 * @brief Label of root CA when calling @ref logPath.
 */
#define ROOT_CA_LABEL        "Root CA certificate"

/**
 * @brief Label of client certificate when calling @ref logPath.
 */
#define CLIENT_CERT_LABEL    "Client's certificate"

/**
 * @brief Label of client key when calling @ref logPath.
 */
#define CLIENT_KEY_LABEL     "Client's key"

#ifdef PUFS_MBEDTLS_KEY_CB_LOG
#define mbedtls_printf printf
#define TLS_KEY_BACKUP        /* Backup key material in internal variable */
//#define PRINT_TLS_KEY_DATA    /* to print tls key and random information */
//#define PRINT_NSS_KEYLOG_LINE  /* to print NSS key logged line */
#endif

/*-----------------------------------------------------------*/

/* Each compilation unit must define the NetworkContext struct. */
struct NetworkContext
{
    MbedtlsContext_t * pParams;
};

/*-----------------------------------------------------------*/

#ifdef PUFS_MBEDTLS_KEY_CB_LOG
#ifdef TLS_KEY_BACKUP
/**
 * @brief Structure to keep tls master secret, random bytyes and tls prf type.
 */
typedef struct tls_keys
{
    unsigned char master_secret[48];
    unsigned char randbytes[64];
    mbedtls_tls_prf_types tls_prf_type;
} tls_keys;

/**
 * @brief Variables for key material.
 */

tls_keys tls_keying;
#endif
#endif


/*-----------------------------------------------------------*/
/**
 * @brief Represents string to be logged when mbedTLS returned error
 * does not contain a high-level code.
 */
static const char * pNoHighLevelMbedTlsCodeStr = "<No-High-Level-Code>";

/**
 * @brief Represents string to be logged when mbedTLS returned error
 * does not contain a low-level code.
 */
static const char * pNoLowLevelMbedTlsCodeStr = "<No-Low-Level-Code>";

/**
 * @brief Utility for converting the high-level code in an mbedTLS error to string,
 * if the code-contains a high-level code; otherwise, using a default string.
 */
#define mbedtlsHighLevelCodeOrDefault( mbedTlsCode )       \
    ( mbedtls_high_level_strerr( mbedTlsCode ) != NULL ) ? \
    mbedtls_high_level_strerr( mbedTlsCode ) : pNoHighLevelMbedTlsCodeStr

/**
 * @brief Utility for converting the level-level code in an mbedTLS error to string,
 * if the code-contains a level-level code; otherwise, using a default string.
 */
#define mbedtlsLowLevelCodeOrDefault( mbedTlsCode )       \
    ( mbedtls_low_level_strerr( mbedTlsCode ) != NULL ) ? \
    mbedtls_low_level_strerr( mbedTlsCode ) : pNoLowLevelMbedTlsCodeStr

/*-----------------------------------------------------------*/
/*        Static Function Declaration                        */
/*-----------------------------------------------------------*/

/**
 * @brief Log possible error from send/recv.
 *
 * @param[in] errorNumber Error number to be logged.
 */
static void logTransportError( int32_t errorNumber );

/**
 * @brief Check if the network context is valid.
 *
 * @param[in] pNetworkContext The network context created using Openssl_Connect API.
 *
 * @return 1 on success; 0 on failure.
 */
static int32_t isValidNetworkContext( const NetworkContext_t * pNetworkContext );


/**
 * @brief Seed random number
 *
 * @param[in] pContext The SSL context to initialize.
 */
static MbedtlsStatus_t mbedtls_rng_seed(MbedtlsContext_t * pContext);

/**
 * @brief Initialize the MbedTLS structures in a network connection.
 *
 * @param[in] pContext The SSL context to initialize.
 */
static void contextInit( MbedtlsContext_t * pContext );

/**
 * @brief Free the MbedTLS structures in a network connection.
 *
 * @param[in] pContext The SSL context to free.
 */
static void contextFree( MbedtlsContext_t * pContext );

/**
 * @brief Configure MbedTLS for TLS on a TCP connection for the
 * client credentials.
 *
 * @param[in] pMbedtlsContext Network context.
 * @param[in] pHostName Remote host name, used for server name indication.
 * @param[in] pMbedtlsCredentials TLS setup parameters.
 * @param[in] recvTimeoutMs Receive timeout for network socket.
 *
 * @return #MBEDTLS_SUCCESS, #MBEDTLS_INSUFFICIENT_MEMORY, #MBEDTLS_INVALID_CREDENTIALS,
 * #MBEDTLS_INVALID_KEY #MBEDTLS_HANDSHAKE_FAILED, or #MBEDTLS_INTERNAL_ERROR.
 */
static MbedtlsStatus_t configureMbedtls( MbedtlsContext_t * pMbedtlsContext,
                                               const char * pHostName,
                                               const MbedtlsCredentials_t * pMbedtlsCredentials,
                                               uint32_t recvTimeoutMs );

/**
 * @brief Configure the client and Root CA in the MbedTLS SSL context.
 *
 * @param[in] pMbedtlsContext Network context.
 * @param[in] pMbedtlsredentials TLS setup parameters.
 *
 * @return #MBEDTLS_SUCCESS on success,
 * #MBEDTLS_INVALID_CREDENTIALS on error.
 */
static MbedtlsStatus_t configureMbedtlsCertificates( MbedtlsContext_t * pMbedtlsContext,
                                                           const MbedtlsCredentials_t * pMbedtlsCredentials );

/**
 * @brief Configure the SNI and ALPN in the MbedTLS SSL context.
 *
 * @param[in] pMbedtlsContext Network context.
 * @param[in] pMbedtlsCredentials TLS setup parameters.
 * @param[in] pHostName Remote host name, used for server name indication.
 *
 * @return #MBEDTLS_SUCCESS on success,
 * #MBEDTLS_INVALID_CREDENTIALS on error.
 */
static MbedtlsStatus_t configureMbedtlsSniAlpn( MbedtlsContext_t * pMbedtlsContext,
                                                      const MbedtlsCredentials_t * pMbedtlsCredentials,
                                                      const char * pHostName );

/**
 * @brief Configure the Maximum Fragment Length in the MbedTLS SSL context.
 *
 * @param[in] pMbedtlsContext Network context.
 *
 * @return #MBEDTLS_SUCCESS on success,
 * #MBEDTLS_INVALID_CREDENTIALS on error.
 */
static MbedtlsStatus_t configureMbedtlsFragmentLength( MbedtlsContext_t * pMbedtlsContext );


/**
 * @brief Helper for configuring MbedTLS to use client private key from PKCS #11.
 *
 * @param pContext Caller context.
 * @param pPrivateKeyPath File path for the private key.
 *
 * @return #MBEDTLS_SUCCESS on success,
 * #MBEDTLS_INVALID_CREDENTIALS on error.
 */
static MbedtlsStatus_t initializeClientKeys( MbedtlsContext_t * pContext,
                                  const char * pPrivateKeyPath );

/**
 * @brief Sign a cryptographic hash with the private key. This is passed as a
 * callback to MbedTLS.
 *
 * @param[in] pContext Crypto context.
 * @param[in] mdAlg Unused.
 * @param[in] pHash Length in bytes of hash to be signed.
 * @param[in] hashLen Byte array of hash to be signed.
 * @param[out] pSig RSA signature bytes.
 * @param[in] pSigLen Length in bytes of signature buffer.
 * @param[in] pRng Unused.
 * @param[in] pRngContext Unused.
 *
 * @return Zero on success.
 */
static int32_t privateKeySigningCallback( void * pContext,
                                          mbedtls_md_type_t mdAlg,
                                          const unsigned char * pHash,
                                          size_t hashLen,
                                          unsigned char * pSig,
                                          size_t * pSigLen,
                                          int32_t ( * pRng )( void *, unsigned char *, size_t ),
                                          void * pRngContext );

static void logTransportError( int32_t errorNumber )
{
    /* Remove unused parameter warning. */
    ( void ) errorNumber;

    LogError( ( "A transport error occurred: %s.", strerror( errorNumber ) ) );
}

/*-----------------------------------------------------------*/

static int32_t isValidNetworkContext( const NetworkContext_t * pNetworkContext )
{
    int32_t isValid = 0;

    if( ( pNetworkContext == NULL ) || ( pNetworkContext->pParams == NULL ) )
    {
        LogError( ( "Parameter check failed: pNetworkContext is NULL." ) );
    }
    else
    {
        isValid = 1;
    }

    return isValid;
}

/*-----------------------------------------------------------*/

static MbedtlsStatus_t mbedtls_rng_seed(MbedtlsContext_t * pContext)
{

    int32_t mbedtlsError = 0;
    char pers[] = "aws iot mbedtls";


    LogInfo( ("Seeding the random number generator...") );

    if( ( mbedtlsError = mbedtls_ctr_drbg_seed( &(pContext->ctr_drbg), mbedtls_entropy_func,
                                                 &(pContext->entropy),
                                                 (const unsigned char *) pers,
                                                 strlen( pers ) ) ) != 0 )
    {

        LogError( ( "Failed\n  ! mbedtls_ctr_drbg_seed : mbedTLSError= %s : %s.",
                    mbedtlsHighLevelCodeOrDefault( mbedtlsError ),
                    mbedtlsLowLevelCodeOrDefault( mbedtlsError ) ) );

        mbedtlsError = MBEDTLS_DRNG_SEED_FAILURE;
    }

    return mbedtlsError;
}

/*-----------------------------------------------------------*/

#ifdef PUFS_MBEDTLS_KEY_CB_LOG
#ifdef PRINT_TLS_KEY_DATA
static void print_buf_hex(char *str, const uint8_t *buf, uint32_t size)
{
     int i = 0;
     if(buf == NULL || size == 0)
     {
          printf("print %s failed invalid pointer buf:%p, size:%d\n", str, buf, size);
     }

     printf("%s, size:%d\n", str, size);
     for ( i = 0; i< size; i++)
     {
         printf("0x%02x ",*(buf+i));
         if ((i%16) ==15)
         {
             printf("\n");
         }
     }
    printf("\n");
}
#endif

/*-----------------------------------------------------------*/
int nss_keylog_export( void *p_expkey,
                       const unsigned char *ms,
                       const unsigned char *kb,
                       size_t maclen,
                       size_t keylen,
                       size_t ivlen,
                       const unsigned char client_random[32],
                       const unsigned char server_random[32],
                       mbedtls_tls_prf_types tls_prf_type )
{
    char nss_key_file_path[]="mbedtls_key_log.txt";
    char nss_keylog_line[ 200 ];
    size_t const client_random_len = 32;
    size_t const master_secret_len = 48;
    size_t len = 0;
    size_t j;
    int ret = 0;

    ((void) p_expkey);
    ((void) kb);
    ((void) maclen);
    ((void) keylen);
    ((void) ivlen);
    ((void) server_random);
    ((void) tls_prf_type);

#ifdef TLS_KEY_BACKUP
    tls_keys *keys = (tls_keys *)p_expkey;
    memcpy( keys->master_secret, ms, master_secret_len );
    memcpy( keys->randbytes, client_random, 32 );
    memcpy( keys->randbytes + 32, server_random, 32 );
    keys->tls_prf_type = tls_prf_type;
#endif

#ifdef PRINT_TLS_KEY_DATA
    printf("nss_keylog_export keylen:%ld, ivlen:%ld, maclen:%ld \n",
            keylen, ivlen, maclen);
    print_buf_hex("master_secret", ms, 48);
    print_buf_hex("client_random", client_random, 32);
    print_buf_hex("server_random", server_random, 32);
#endif


    len += sprintf( nss_keylog_line + len,
                    "%s", "CLIENT_RANDOM " );

    for( j = 0; j < client_random_len; j++ )
    {
        len += sprintf( nss_keylog_line + len,
                        "%02x", client_random[j] );
    }

    len += sprintf( nss_keylog_line + len, " " );

    for( j = 0; j < master_secret_len; j++ )
    {
        len += sprintf( nss_keylog_line + len,
                        "%02x", ms[j] );
    }

    len += sprintf( nss_keylog_line + len, "\n" );
    nss_keylog_line[ len ] = '\0';

#ifdef PRINT_NSS_KEYLOG_LINE
    mbedtls_printf( "\n" );
    mbedtls_printf( "---------------- NSS KEYLOG -----------------\n" );
    mbedtls_printf( "%s", nss_keylog_line );
    mbedtls_printf( "---------------------------------------------\n" );
#endif

    if( nss_key_file_path != NULL )
    {
        FILE *f;

        if( ( f = fopen( nss_key_file_path, "a" ) ) == NULL )
        {
            ret = -1;
            goto exit;
        }

        if( fwrite( nss_keylog_line, 1, len, f ) != len )
        {
            ret = -1;
            fclose( f );
            goto exit;
        }

        fclose( f );
    }

exit:
    mbedtls_platform_zeroize( nss_keylog_line,
                              sizeof( nss_keylog_line ) );
    return( ret );
}

/*-----------------------------------------------------------*/

void mbedtls_ctx_key_cb_config( MbedtlsContext_t * pContext)
{
    mbedtls_ssl_config *conf = &(pContext->config);

    mbedtls_ssl_conf_export_keys_ext_cb( conf,
                                         nss_keylog_export,
                                         &tls_keying );

}
#endif /* PUFS_MBEDTLS_KEY_CB_LOG */

/*-----------------------------------------------------------*/

// Note : mbedtls configuration refers to codes in below files
//        main function of ssl_clinet1.c/ssl_clkent2.c in mbedtls/program/ssl
//        mbedtls_pcks11_posix.c and mbedtls_pcks11_posix.h

static void contextInit( MbedtlsContext_t * pContext )
{
    assert( pContext != NULL );

    mbedtls_net_init( &( pContext->socketContext ) );
    mbedtls_ssl_init( &( pContext->context ) );
    mbedtls_ssl_config_init( &( pContext->config ) );
    mbedtls_x509_crt_init( &( pContext->rootCa ) );
    mbedtls_x509_crt_init( &( pContext->clientCert ) );
#if 1
    mbedtls_ctr_drbg_init( &(pContext->ctr_drbg) );
    mbedtls_entropy_init( &(pContext->entropy) );
#endif

}


/*-----------------------------------------------------------*/

static void contextFree( MbedtlsContext_t * pContext )
{
    if( pContext != NULL )
    {
        mbedtls_net_free( &( pContext->socketContext ) );
        mbedtls_ssl_free( &( pContext->context ) );
        mbedtls_ssl_config_free( &( pContext->config ) );
        mbedtls_x509_crt_free( &( pContext->rootCa ) );
        mbedtls_x509_crt_free( &( pContext->clientCert ) );
#if 1
        mbedtls_ctr_drbg_free( &( pContext->ctr_drbg ) );
        mbedtls_entropy_free( &( pContext->entropy) );
#endif
    }
}

/*-----------------------------------------------------------*/

static void mbedtlsDebugPrint( void * ctx,
                               int level,
                               const char * pFile,
                               int line,
                               const char * pStr )
{
    /* Unused parameters. */
    ( void ) ctx;
    ( void ) pFile;
    ( void ) line;

    /* Send the debug string to the portable logger. */
    printf( "mbedTLS: |%d| %s", level, pStr );
}


/*-----------------------------------------------------------*/

static MbedtlsStatus_t configureMbedtls( MbedtlsContext_t * pMbedtlsContext,
                                               const char * pHostName,
                                               const MbedtlsCredentials_t * pMbedtlsCredentials,
                                               uint32_t recvTimeoutMs )
{
    MbedtlsStatus_t returnStatus = MBEDTLS_SUCCESS;
    int32_t mbedtlsError = 0;

    assert( pMbedtlsContext != NULL );
    assert( pHostName != NULL );
    assert( pMbedtlsCredentials != NULL );
    assert( pMbedtlsCredentials->pRootCaPath != NULL );

    /* Initialize the MbedTLS context structures. */
    contextInit( pMbedtlsContext );

    mbedtlsError = mbedtls_rng_seed(pMbedtlsContext);

    if (mbedtlsError == MBEDTLS_SUCCESS)
    {
         mbedtlsError = mbedtls_ssl_config_defaults( &( pMbedtlsContext->config ),
                                                    MBEDTLS_SSL_IS_CLIENT,
                                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                                    MBEDTLS_SSL_PRESET_DEFAULT );
    }

    if( mbedtlsError != 0 )
    {
        LogError( ( "Failed to set default SSL configuration: mbedTLSError= %s : %s.",
                    mbedtlsHighLevelCodeOrDefault( mbedtlsError ),
                    mbedtlsLowLevelCodeOrDefault( mbedtlsError ) ) );

        /* Per MbedTLS docs, mbedtls_ssl_config_defaults only fails on memory allocation. */
        returnStatus = MBEDTLS_INSUFFICIENT_MEMORY;
    }
    else
    {
        /* Set up the certificate security profile, starting from the default value. */
        pMbedtlsContext->certProfile = mbedtls_x509_crt_profile_default;

        /* Set SSL authmode and the RNG context. */
        mbedtls_ssl_conf_authmode( &( pMbedtlsContext->config ), MBEDTLS_SSL_VERIFY_REQUIRED );

        #if 1 //PUFS
        //To do: use pufse to generate random number bytes
        mbedtls_ssl_conf_rng( &( pMbedtlsContext->config ), mbedtls_ctr_drbg_random, &(pMbedtlsContext->ctr_drbg) );
        #else
        mbedtls_ssl_conf_rng( &( pMbedtlsContext->config ), generateRandomBytes, pMbedtlsContext );
        #endif
        mbedtls_ssl_conf_cert_profile( &( pMbedtlsContext->config ), &( pMbedtlsContext->certProfile ) );
        mbedtls_ssl_conf_read_timeout( &( pMbedtlsContext->config ), recvTimeoutMs );
        mbedtls_ssl_conf_dbg( &pMbedtlsContext->config, mbedtlsDebugPrint, NULL );
        mbedtls_debug_set_threshold( MBEDTLS_DEBUG_LOG_LEVEL );

#ifdef PUFS_MBEDTLS_KEY_CB_LOG
        mbedtls_ctx_key_cb_config( pMbedtlsContext );
#endif

        //parse ca and device certificates
        returnStatus = configureMbedtlsCertificates( pMbedtlsContext, pMbedtlsCredentials );
    }

    if( returnStatus == MBEDTLS_SUCCESS )
    {
        returnStatus = configureMbedtlsSniAlpn( pMbedtlsContext, pMbedtlsCredentials, pHostName );
    }

    if( returnStatus == MBEDTLS_SUCCESS )
    {
        /* Initialize the MbedTLS secured connection context. */
        mbedtlsError = mbedtls_ssl_setup( &( pMbedtlsContext->context ),
                                          &( pMbedtlsContext->config ) );

        if( mbedtlsError != 0 )
        {
            LogError( ( "Failed to set up MbedTLS SSL context: mbedTLSError= %s : %s.",
                        mbedtlsHighLevelCodeOrDefault( mbedtlsError ),
                        mbedtlsLowLevelCodeOrDefault( mbedtlsError ) ) );
            returnStatus = MBEDTLS_INTERNAL_ERROR;
        }
    }

    if( returnStatus == MBEDTLS_SUCCESS )
    {
        /* Set the underlying IO for the TLS connection. */
        mbedtls_ssl_set_bio( &( pMbedtlsContext->context ),
                             ( void * ) &( pMbedtlsContext->socketContext ),
                             mbedtls_net_send,
                             mbedtls_net_recv,
                             mbedtls_net_recv_timeout );

        returnStatus = configureMbedtlsFragmentLength( pMbedtlsContext );
    }

    if( returnStatus != MBEDTLS_SUCCESS )
    {
        contextFree( pMbedtlsContext );
    }
    else
    {
        LogDebug( ( "Configured MbedTLS context." ) );
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static MbedtlsStatus_t configureMbedtlsCertificates( MbedtlsContext_t * pMbedtlsContext,
                                                           const MbedtlsCredentials_t * pMbedtlsCredentials )

{
    MbedtlsStatus_t returnStatus = MBEDTLS_SUCCESS;
    int32_t mbedtlsError = 0;
    bool result;

    assert( pMbedtlsContext != NULL );
    assert( pMbedtlsCredentials != NULL );
    assert( pMbedtlsCredentials->pRootCaPath != NULL );


    /* Parse the server root CA certificate into the SSL context. */
    mbedtlsError = mbedtls_x509_crt_parse_file( &( pMbedtlsContext->rootCa ),
                                                pMbedtlsCredentials->pRootCaPath );

    if( mbedtlsError != 0 )
    {
        LogError( ( "Failed to parse server root CA certificate: mbedTLSError= %s : %s.",
                    mbedtlsHighLevelCodeOrDefault( mbedtlsError ),
                    mbedtlsLowLevelCodeOrDefault( mbedtlsError ) ) );
        returnStatus = MBEDTLS_INVALID_CREDENTIALS;
    }
    else
    {
        mbedtls_ssl_conf_ca_chain( &( pMbedtlsContext->config ),
                                   &( pMbedtlsContext->rootCa ),
                                   NULL );

        /* Setup the client private key. */
        returnStatus = initializeClientKeys( pMbedtlsContext,
                                       pMbedtlsCredentials->pPrivateKeyPath );

        if( returnStatus != MBEDTLS_SUCCESS )
        {
            LogError( ( "Failed to setup key handling by mbedtls." ) );
        }
    }

    if( returnStatus == MBEDTLS_SUCCESS )
    {
        /* Parse the client certificate into the SSL context. */
        mbedtlsError = mbedtls_x509_crt_parse_file( &( pMbedtlsContext->clientCert ),
                                                        pMbedtlsCredentials->pClientCertPath );
        if( mbedtlsError != 0 )
        {
            LogError( ( "Failed to parse client certificate: mbedTLSError= %s : %s.",
                         mbedtlsHighLevelCodeOrDefault( mbedtlsError ),
                         mbedtlsLowLevelCodeOrDefault( mbedtlsError ) ) );
            returnStatus = MBEDTLS_INVALID_CREDENTIALS;
        }
    }

    if( returnStatus == MBEDTLS_SUCCESS )
    {
        ( void ) mbedtls_ssl_conf_own_cert( &( pMbedtlsContext->config ),
                                            &( pMbedtlsContext->clientCert ),
                                            &( pMbedtlsContext->privKey ) );
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static MbedtlsStatus_t configureMbedtlsSniAlpn( MbedtlsContext_t * pMbedtlsContext,
                                                      const MbedtlsCredentials_t * pMbedtlsCredentials,
                                                      const char * pHostName )
{
    MbedtlsStatus_t returnStatus = MBEDTLS_SUCCESS;
    int32_t mbedtlsError = 0;

    assert( pMbedtlsContext != NULL );
    assert( pHostName != NULL );
    assert( pMbedtlsCredentials != NULL );
    assert( pMbedtlsCredentials->pRootCaPath != NULL );

    if( pMbedtlsCredentials->pAlpnProtos != NULL )
    {
        /* Include an application protocol list in the TLS ClientHello message. */
        mbedtlsError = mbedtls_ssl_conf_alpn_protocols( &( pMbedtlsContext->config ),
                                                        pMbedtlsCredentials->pAlpnProtos );

        if( mbedtlsError != 0 )
        {
            LogError( ( "Failed to configure ALPN protocol in MbedTLS: mbedTLSError= %s : %s.",
                        mbedtlsHighLevelCodeOrDefault( mbedtlsError ),
                        mbedtlsLowLevelCodeOrDefault( mbedtlsError ) ) );
            returnStatus = MBEDTLS_INTERNAL_ERROR;
        }
    }

    /* Enable SNI if requested. */
    if( ( returnStatus == MBEDTLS_SUCCESS ) &&
        ( pMbedtlsCredentials->disableSni == false ) )
    {
        mbedtlsError = mbedtls_ssl_set_hostname( &( pMbedtlsContext->context ),
                                                 pHostName );

        if( mbedtlsError != 0 )
        {
            LogError( ( "Failed to set server name: mbedTLSError= %s : %s.",
                        mbedtlsHighLevelCodeOrDefault( mbedtlsError ),
                        mbedtlsLowLevelCodeOrDefault( mbedtlsError ) ) );
            returnStatus = MBEDTLS_INTERNAL_ERROR;
        }
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static MbedtlsStatus_t configureMbedtlsFragmentLength( MbedtlsContext_t * pMbedtlsContext )
{
    MbedtlsStatus_t returnStatus = MBEDTLS_SUCCESS;
    int32_t mbedtlsError = 0;

    assert( pMbedtlsContext != NULL );

    /* Set Maximum Fragment Length if enabled. */
    #ifdef MBEDTLS_SSL_MAX_FRAGMENT_LENGTH

        /* Enable the max fragment extension. 4096 bytes is currently the largest fragment size permitted.
         * See RFC 6066 https://tools.ietf.org/html/rfc6066#page-8 for more information.
         *
         * Smaller values can be found in "mbedtls/include/ssl.h".
         */
        mbedtlsError = mbedtls_ssl_conf_max_frag_len( &( pMbedtlsContext->config ), MBEDTLS_SSL_MAX_FRAG_LEN_4096 );

        if( mbedtlsError != 0 )
        {
            LogError( ( "Failed to maximum fragment length extension: mbedTLSError= %s : %s.",
                        mbedtlsHighLevelCodeOrDefault( mbedtlsError ),
                        mbedtlsLowLevelCodeOrDefault( mbedtlsError ) ) );
            returnStatus = MBEDTLS_INTERNAL_ERROR;
        }
    #endif /* ifdef MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */
    return returnStatus;
}


/*-----------------------------------------------------------*/

static MbedtlsStatus_t initializeClientKeys( MbedtlsContext_t * pContext,
                                  const char * pPrivateKeyPath )
{
    int32_t mbedtlsError = MBEDTLS_SUCCESS;
    MbedtlsStatus_t returnStatus = MBEDTLS_SUCCESS;
    mbedtls_pk_context pkey;

    assert( pContext != NULL );
    assert( pPrivateKeyPath != NULL );

    mbedtls_pk_init(&pkey);

    //pkey.pk_ctx : pointer to key data, this buffer is allocate when parsing key file
    //pkey.pk_info : key function handler (ex sign, verify...)
    mbedtlsError = mbedtls_pk_parse_keyfile(&pkey, pPrivateKeyPath, NULL);

    if( mbedtlsError != 0 )
    {
        LogError( ( "Failed to parse client key file:%s mbedTLSError= %s : %s.",
                     pPrivateKeyPath,
                     mbedtlsHighLevelCodeOrDefault( mbedtlsError ),
                     mbedtlsLowLevelCodeOrDefault( mbedtlsError ) ) );
        returnStatus = MBEDTLS_INVALID_KEY;
    }
    else
    {
        /* Map the mbedTLS algorithm to mbedtls context internal metadata. (privKeyInfo) */
        memcpy( &pContext->privKeyInfo, pkey.pk_info, sizeof( mbedtls_pk_info_t ) );
        pContext->privKeyInfo.sign_func = privateKeySigningCallback;
        pContext->privKey = pkey;
    }


    return( returnStatus );
}

/*-----------------------------------------------------------*/
static int32_t privateKeySigningCallback( void * pContext,
                                          mbedtls_md_type_t mdAlg,
                                          const unsigned char * pHash,
                                          size_t hashLen,
                                          unsigned char * pSig,
                                          size_t * pSigLen,
                                          int32_t ( * pRng )( void *,
                                                              unsigned char *,
                                                              size_t ),
                                          void * pRngContext )
{
    int32_t ret = MBEDTLS_SUCCESS;
    int32_t result = 0;
    MbedtlsContext_t * pMbedtlsContext = ( MbedtlsContext_t * ) pContext;

    /* Buffer big enough to hold data to be signed. */
    unsigned char toBeSigned[ 256 ];
    uint32_t toBeSignedLen = sizeof( toBeSigned );

    LogInfo( ("privateKeySigningCallback contx:0x%p\n", pContext) );

    assert( pContext != NULL );
    assert( pHash != NULL );
    assert( pSigLen != NULL );
    assert( pSig != NULL );
    assert( pRng != NULL );
    assert( pRngContext != NULL );

    /* Sanity check buffer length. */
    if( hashLen > sizeof( toBeSigned ) )
    {
        ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    else
    {
        memcpy( toBeSigned, pHash, hashLen );
        toBeSignedLen = hashLen;
    }

    const mbedtls_pk_info_t* pk_info;

    /* Format the hash data to be signed. */
    if( pMbedtlsContext->privKeyInfo.type == MBEDTLS_PK_RSA )
    {

        pk_info = &mbedtls_eckey_info;


        result = pk_info->verify_func((pMbedtlsContext->privKey.pk_ctx), mdAlg, toBeSigned, toBeSignedLen,
                                       pSig, *pSigLen );
    }
    else if( pMbedtlsContext->privKeyInfo.type == MBEDTLS_PK_ECDSA )
    {
        pk_info = &mbedtls_eckey_info;
        result = pk_info->verify_func((pMbedtlsContext->privKey.pk_ctx), mdAlg, toBeSigned, toBeSignedLen,
                                       pSig, *pSigLen );
    }
    else
    {
        result = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }


    if( result != MBEDTLS_SUCCESS )
    {
        LogError( ( "Failed to sign message  algo:%d mbedTLSError= %s : %s.",
                     pMbedtlsContext->privKeyInfo.type,
                     mbedtlsHighLevelCodeOrDefault( result ),
                     mbedtlsLowLevelCodeOrDefault( result ) ) );
    }

    return result;
}


/*-----------------------------------------------------------*/

MbedtlsStatus_t Mbedtls_Connect( NetworkContext_t * pNetworkContext,
                                 const char * pHostName,
                                 uint16_t port,
                                 const MbedtlsCredentials_t * pMbedtlsCredentials,
                                 uint32_t recvTimeoutMs )
{
    MbedtlsContext_t * pMbedtlsContext = NULL;
    MbedtlsStatus_t returnStatus = MBEDTLS_SUCCESS;
    int32_t mbedtlsError = 0;
    char portStr[ 6 ] = { 0 };

    /* Validate parameters. */
    if( ( pNetworkContext == NULL ) ||
        ( pNetworkContext->pParams == NULL ) ||
        ( pHostName == NULL ) ||
        ( pMbedtlsCredentials == NULL ) ||
        ( pMbedtlsCredentials->pRootCaPath == NULL ) ||
        ( pMbedtlsCredentials->pClientCertPath == NULL ) ||
        ( pMbedtlsCredentials->pPrivateKeyPath == NULL ) )
    {
        LogError( ( "Invalid input parameter(s): Arguments cannot be NULL. pNetworkContext=%p, "
                    "pHostName=%p, pMbedtlsCredentials=%p.",
                    ( void * ) pNetworkContext,
                    ( const void * ) pHostName,
                    ( const void * ) pMbedtlsCredentials ) );
        returnStatus = MBEDTLS_INVALID_PARAMETER;
    }
    else
    {
        snprintf( portStr, sizeof( portStr ), "%u", port );
        pMbedtlsContext = pNetworkContext->pParams;

        /* Configure MbedTLS. */
        returnStatus = configureMbedtls( pMbedtlsContext, pHostName, pMbedtlsCredentials,
                                         recvTimeoutMs );

    }

    /* Establish a TCP connection with the server. */
    if( returnStatus == MBEDTLS_SUCCESS )
    {
        mbedtlsError = mbedtls_net_connect( &( pMbedtlsContext->socketContext ),
                                            pHostName,
                                            portStr,
                                            MBEDTLS_NET_PROTO_TCP );

        if( mbedtlsError != 0 )
        {
            LogError( ( "Failed to connect to %s with error %d.", pHostName, mbedtlsError ) );
            returnStatus = MBEDTLS_CONNECT_FAILURE;
        }
    }

    if( returnStatus == MBEDTLS_SUCCESS )
    {
        /* Perform the TLS handshake. */
        do
        {
            mbedtlsError = mbedtls_ssl_handshake( &( pMbedtlsContext->context ) );
        } while( ( mbedtlsError == MBEDTLS_ERR_SSL_WANT_READ ) ||
                 ( mbedtlsError == MBEDTLS_ERR_SSL_WANT_WRITE ) );

        if( ( mbedtlsError != 0 ) || ( mbedtls_ssl_get_verify_result( &( pMbedtlsContext->context ) ) != 0U ) )
        {
            LogError( ( "Failed to perform TLS handshake: mbedTLSError= %s : %s.",
                        mbedtlsHighLevelCodeOrDefault( mbedtlsError ),
                        mbedtlsLowLevelCodeOrDefault( mbedtlsError ) ) );
            returnStatus = MBEDTLS_HANDSHAKE_FAILED;
        }
    }

    /* Clean up on failure. */
    if( returnStatus != MBEDTLS_SUCCESS )
    {
        contextFree( pMbedtlsContext );
    }
    else
    {
        LogInfo( ( "TLS Connection to %s established.", pHostName ) );
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

void Mbedtls_Disconnect( const NetworkContext_t * pNetworkContext )
{
    MbedtlsContext_t * pMbedtlsContext = NULL;
    int tlsStatus = 0;

    /* Validate parameters. */
    if( ( pNetworkContext != NULL ) || ( pNetworkContext->pParams != NULL ) )
    {

        pMbedtlsContext = pNetworkContext->pParams;

        /* Attempting to terminate TLS connection. */
        tlsStatus = mbedtls_ssl_close_notify( &( pMbedtlsContext->context ) );

        if( tlsStatus == 0 )
        {
            LogInfo( ( "Closing TLS connection: TLS close-notify sent." ) );
        }
        else if( ( tlsStatus == MBEDTLS_ERR_SSL_WANT_READ ) ||
                 ( tlsStatus == MBEDTLS_ERR_SSL_WANT_WRITE ) )
        {
            /* WANT_READ or WANT_WRITE can be ignored. Logging for debugging purposes. */
            LogInfo( ( "TLS close-notify sent; "
                       "received %s as the TLS status which can be ignored for close-notify.",
                       ( tlsStatus == MBEDTLS_ERR_SSL_WANT_READ ) ? "WANT_READ" : "WANT_WRITE" ) );
        }
        else
        {
            /* Ignore the WANT_READ or WANT_WRITE return values. */
            LogError( ( "Failed to send TLS close-notify: mbedTLSError= %s : %s.",
                        mbedtlsHighLevelCodeOrDefault( tlsStatus ),
                        mbedtlsLowLevelCodeOrDefault( tlsStatus ) ) );
        }

        /* Free contexts. */
        contextFree( pMbedtlsContext );

    }
    else
    {
        LogError( ( "Parameter check failed: pNetworkContext or -> pParams is NULL." ) );

    }

}

/*-----------------------------------------------------------*/

int32_t Mbedtls_Recv( NetworkContext_t * pNetworkContext,
                      void * pBuffer,
                      size_t bytesToRecv )
{
    MbedtlsContext_t * pMbedtlsContext = NULL;
    int32_t tlsStatus = 0;

    if (!isValidNetworkContext( pNetworkContext ) ||
           ( pBuffer == NULL )                    ||
           ( bytesToRecv == 0 ) )
    {

        LogError( ( "Parameter check failed: invalid input, pNetworkContext "
                    "is invalid or pBuffer = %p, bytesToRecv = %lu", pBuffer, bytesToRecv ) );
        return -1;

    }


    pMbedtlsContext = pNetworkContext->pParams;
    tlsStatus = ( int32_t ) mbedtls_ssl_read( &( pMbedtlsContext->context ),
                                              pBuffer,
                                              bytesToRecv );


    if( ( tlsStatus == MBEDTLS_ERR_SSL_TIMEOUT ) ||
        ( tlsStatus == MBEDTLS_ERR_SSL_WANT_READ ) ||
        ( tlsStatus == MBEDTLS_ERR_SSL_WANT_WRITE ) )
    {
        LogDebug( ( "Failed to read data. However, a read can be retried on this error. "
                    "mbedTLSError= %s : %s.",
                    mbedtlsHighLevelCodeOrDefault( tlsStatus ),
                    mbedtlsLowLevelCodeOrDefault( tlsStatus ) ) );

        /* Mark these set of errors as a timeout. The libraries may retry read
         * on these errors. */
        tlsStatus = 0;
    }
    else if( tlsStatus < 0 )
    {
        LogError( ( "Failed to read data: mbedTLSError= %s : %s.",
                    mbedtlsHighLevelCodeOrDefault( tlsStatus ),
                    mbedtlsLowLevelCodeOrDefault( tlsStatus ) ) );
    }
    else
    {
        /* Empty else marker. */
    }

    return tlsStatus;
}

/*-----------------------------------------------------------*/

int32_t Mbedtls_Send( NetworkContext_t * pNetworkContext,
                       const void * pBuffer,
                       size_t bytesToSend )
{
    MbedtlsContext_t * pMbedtlsContext = NULL;
    int32_t tlsStatus = 0;

    if (!isValidNetworkContext( pNetworkContext ) ||
        ( pBuffer == NULL )                       ||
        ( bytesToSend == 0 ) )
    {

        LogError( ( "Parameter check failed: invalid input, pNetworkContext "
                    "is invalid or pBuffer = %p, bytesToSend = %lu", pBuffer, bytesToSend ) );
        return -1;

    }

    pMbedtlsContext = pNetworkContext->pParams;
    tlsStatus = ( int32_t ) mbedtls_ssl_write( &( pMbedtlsContext->context ),
                                                pBuffer,
                                                bytesToSend );

    if( ( tlsStatus == MBEDTLS_ERR_SSL_TIMEOUT ) ||
         ( tlsStatus == MBEDTLS_ERR_SSL_WANT_READ ) ||
         ( tlsStatus == MBEDTLS_ERR_SSL_WANT_WRITE ) )
    {
        LogDebug( ( "Failed to send data. However, send can be retried on this error. "
                     "mbedTLSError= %s : %s.",
                     mbedtlsHighLevelCodeOrDefault( tlsStatus ),
                     mbedtlsLowLevelCodeOrDefault( tlsStatus ) ) );

         /* Mark these set of errors as a timeout. The libraries may retry send
          * on these errors. */
         tlsStatus = 0;
    }
    else if( tlsStatus < 0 )
    {
        LogError( ( "Failed to send data:  mbedTLSError= %s : %s.",
                     mbedtlsHighLevelCodeOrDefault( tlsStatus ),
                     mbedtlsLowLevelCodeOrDefault( tlsStatus ) ) );
    }
    else
    {
        /* Empty else marker. */
    }

    return tlsStatus;
}
/*-----------------------------------------------------------*/
