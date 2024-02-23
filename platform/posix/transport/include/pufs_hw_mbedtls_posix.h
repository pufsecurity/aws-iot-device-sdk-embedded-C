/***********************************************************************************
 *
 * Copyright (C) 2023-2024 PUFsecurity and/or its affiliates. All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 *
 **************************************************************************************/

/*
 * AWS IoT Device SDK for Embedded C 202211.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
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


#ifndef PUFS_HW_MBEDTLS_POSIX_H_
#define PUFS_HW_MBEDTLS_POSIX_H_
/**
 * @file pufs_hw_mbedtls_posix_pufs.h
 *
 * @brief Implementation for the transport interface using a mutually
 * authenticated TLS connection with MbedTLS for TLS  for secure
 * credential management.
 * This file references to plaintext_posix.h and openssl_posix.h
 */

/**************************************************/
/******* DO NOT CHANGE the following order ********/
/**************************************************/

/* Logging related header files are required to be included in the following order:
 * 1. Include the header file "logging_levels.h".
 * 2. Define LIBRARY_LOG_NAME and  LIBRARY_LOG_LEVEL.
 * 3. Include the header file "logging_stack.h".
 */

/* Include header that defines log levels. */
#include "logging_levels.h"


#if DEMO_LOG_LEVEL == 0
   #define LIBRARY_LOG_LEVEL    LOG_WARN
#else
   #define LIBRARY_LOG_LEVEL    LOG_DEBUG
#endif


/* Logging configuration for the transport interface implementation which uses
 * MbedTLS and Sockets. */
#ifndef LIBRARY_LOG_NAME
    #define LIBRARY_LOG_NAME     "Transport_MbedTLS_Sockets"
#endif
#ifndef LIBRARY_LOG_LEVEL
    #define LIBRARY_LOG_LEVEL    LOG_DEBUG
#endif

#include "logging_stack.h"


/************ End of logging configuration ****************/

/* *INDENT-OFF* */
#ifdef __cplusplus
    extern "C" {
#endif
/* *INDENT-ON* */

/* Standard includes. */
#include <stdbool.h>

/* MbedTLS includes. */
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/pk.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"


/* Transport includes. */
#include "transport_interface.h"

#ifdef PUFS_HW
/* PUFsecurity security module include */
#include "pufs_util_sec.h"
#endif


/**
 * @brief Debug logging level to use for MbedTLS.
 *
 * @note The default value of 0 disables MbedTLS logging.
 * See https://tls.mbed.org/api/debug_8h.html#a6629362e96b43725ace95c8ff01d9985
 * for valid values.
 */

#ifndef MBEDTLS_DEBUG_LOG_LEVEL
    #define MBEDTLS_DEBUG_LOG_LEVEL    0
#endif


/**
 * @brief Parameters for the transport-interface
 * implementation that uses MbedTls and POSIX sockets.
 *
 * @note For this transport implementation, the socket descriptor and
 * SSL context is used.
 */
typedef struct MbedTlsParams
{
    int32_t socketDescriptor;

} MbedTlsParams_t;


#ifdef PUFS_HW
typedef struct pufs_mbedtls_dev_key_info
{
    bool      dev_hw_key;                  /**< @brief pufs device use hardware private key */
    uint8_t   dev_key_slot;                /**< @brief pufs device private key slot */
    pufs_ec_point_st dev_pub_key;          /**< @brief pufs device ec public key */
    pufs_util_sec_key_algo_t  algo;        /**< @brief pufs device key algorithm */

}pufs_mbedtls_dev_key_info_t;
#endif
/**
 * @brief Context containing state for the MbedTLS and corePKCS11 based
 * transport interface implementation.
 *
 * @note Applications using this transport interface implementation should use
 * this struct as the #NetworkContext_t for the transport interface
 * configuration passed to coreMQTT or coreHTTP.
 */
typedef struct MbedtlsContext
{
    mbedtls_net_context socketContext;    /**< @brief MbedTLS socket context. */
    mbedtls_ssl_config config;            /**< @brief SSL connection configuration. */
    mbedtls_ssl_context context;          /**< @brief SSL connection context */
    mbedtls_x509_crt_profile certProfile; /**< @brief Certificate security profile for this connection. */
    mbedtls_x509_crt rootCa;              /**< @brief Root CA certificate context. */
    mbedtls_x509_crt clientCert;          /**< @brief Client certificate context. */
    mbedtls_pk_context privKey;           /**< @brief Client private key context. */
    mbedtls_pk_info_t privKeyInfo;        /**< @brief Client private key info. */
#ifdef PUFS_HW
    pufs_mbedtls_dev_key_info_t  pufsDevKeyInfo;    /**< @brief PUFsecurity Client Device Key Info */
#endif


    mbedtls_entropy_context entropy;     /**< @brief Mbedtls Entropy context. */
    mbedtls_ctr_drbg_context ctr_drbg;   /**< @brief Mbedtls CTR_DRBG context. */


} MbedtlsContext_t;

/**
 * @brief Contains the credentials necessary for tls connection setup.
 */
typedef struct MbedtlsCredentials
{
    /**
     * @brief To use ALPN, set this to a NULL-terminated list of supported
     * protocols in decreasing order of preference.
     *
     * See [this link]
     * (https://aws.amazon.com/blogs/iot/mqtt-with-tls-client-authentication-on-port-443-why-it-is-useful-and-how-it-works/)
     * for more information.
     */
    const char ** pAlpnProtos;

    /**
     * @brief Disable server name indication (SNI) for a TLS session.
     */
    bool disableSni;

     /**
     * @brief Filepaths to certificates and private key that are used when
     * performing the TLS handshake.
     *
     * @note These strings must be NULL-terminated because the Mbedtls API requires them to be.
     */
    const char * pRootCaPath;     /**< @brief Filepath string to the trusted server root certificate. */
    const char * pClientCertPath; /**< @brief Filepath string to the client certificate. */
    const char * pPrivateKeyPath; /**< @brief Filepath string to the client certificate's private key. */
#ifdef PUFS
    bool  pufDevKey;     /**< @brief Indicate use puf generated device key. */
#endif

} MbedtlsCredentials_t;

/**
 * @brief TLS Connect / Disconnect return status.
 */
typedef enum MbedtlsStatus
{
    MBEDTLS_SUCCESS = 0,         /**< Function successfully completed. */
    MBEDTLS_INVALID_PARAMETER,   /**< At least one parameter was invalid. */
    MBEDTLS_INSUFFICIENT_MEMORY, /**< Insufficient memory required to establish connection. */
    MBEDTLS_INVALID_CREDENTIALS, /**< Provided credentials were invalid. */
    MBEDTLS_INVALID_KEY,         /**< Provided key were invalid. */
    MBEDTLS_HANDSHAKE_FAILED,    /**< Performing TLS handshake with server failed. */
    MBEDTLS_INTERNAL_ERROR,      /**< A call to a system API resulted in an internal error. */
    MBEDTLS_CONNECT_FAILURE,     /**< Initial connection to the server failed. */
    MBEDTLS_DRNG_SEED_FAILURE    /**< DRNG seed failed. */
} MbedtlsStatus_t;


/**
 * @brief Sets up a mutually authenticated TLS session on top of a TCP
 * connection using the MbedTLS library for TLS.
 *
 * @param[out] pNetworkContext The output parameter to return the created network context.
 * @param[in] pHostName The hostname of the remote endpoint.
 * @param[in] port The destination port.
 * @param[in] pMbedtlsCredentials Credentials for the TLS connection.
 * @param[in] recvTimeoutMs Timeout for transport recv.
 *
 * @note A timeout of 0 means infinite timeout.
 *
 * @return #MBEDTLS_SUCCESS if successful;
 * #MBEDTLS_INVALID_PARAMETER, #MBEDTLS_INSUFFICIENT_MEMORY, #MBEDTLS_INVALID_CREDENTIALS
 * #MBEDTLS_HANDSHAKE_FAILED, #MBEDTLS_INTERNAL_ERROR, or #MBEDTLS_CONNECT_FAILURE
 * on failure.
 */
MbedtlsStatus_t Mbedtls_Connect( NetworkContext_t * pNetworkContext,
                                 const char * pHostName,
                                 uint16_t port,
                                 const MbedtlsCredentials_t * pMbedtlsCredentials,
                                 uint32_t recvTimeoutMs );

/**
 * @brief Gracefully disconnect an established TLS connection.
 *
 * @param[in] pNetworkContext The network context to close the connection.
 *
 */
void Mbedtls_Disconnect( const NetworkContext_t * pNetworkContext );

/**
 * @brief Receives data over an established TLS session using MbedTLS API.
 *
 * This can be used as #TransportInterface.recv function to receive data over
 * the network.
 *
 * @param[in] pNetworkContext The network context created using Mbedtls_Connect API.
 * @param[out] pBuffer Buffer to receive network data into.
 * @param[in] bytesToRecv Number of bytes requested from the network.
 *
 * @return Number of bytes received if successful; negative value on error.
 */
int32_t Mbedtls_Recv( NetworkContext_t * pNetworkContext,
                      void * pBuffer,
                      size_t bytesToRecv );

/**
 * @brief Sends data over an established TCP connection.
 *
 * This can be used as the #TransportInterface.send function to send data
 * over the network.
 *
 * @param[in] pNetworkContext The network context created using Mbedtls_Connect API.
 * @param[in] pBuffer Buffer containing the bytes to send over the network.
 * @param[in] bytesToSend Number of bytes to send over the network.
 *
 * @return Number of bytes sent if successful; negative value on error.
 */
int32_t Mbedtls_Send( NetworkContext_t * pNetworkContext,
                      const void * pBuffer,
                      size_t bytesToSend );

/* *INDENT-OFF* */
#ifdef __cplusplus
    }
#endif
/* *INDENT-ON* */

#endif /* ifndef PUFS_HW_MBEDTLS_POSIX_H_ */
