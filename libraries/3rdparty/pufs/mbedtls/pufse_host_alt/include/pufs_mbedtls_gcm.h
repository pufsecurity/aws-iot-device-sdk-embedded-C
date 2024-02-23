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
 *@file        pufs_mbedtls_gcm.h
 *
 *@brief       This file contains PUFsecurity crypto gcm definitions and functions for mbedtls.
 *
 *             Below information is from mbedtls/include/mbedtls/gcm.h:
 *
 *             The Galois/Counter Mode (GCM) for 128-bit block ciphers is defined
 *             in <em>D. McGrew, J. Viega, The Galois/Counter Mode of Operation
 *             (GCM), Natl. Inst. Stand. Technol.</em>
 *
 *             For more information on GCM, see <em>NIST SP 800-38D: Recommendation for
 *             Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC</em>.
 *
 *@copyright   2023-2024 PUFsecurity
 *
 ***************************************************************************************/

#ifndef PUFS_MBEDTLS_GCM_H
#define PUFS_MBEDTLS_GCM_H



#include "gcm_alt.h"


#ifdef __cplusplus
extern "C" {
#endif


/**
 * \brief           This function reset data information in a GCM context
 *
 * \param ctx       The GCM context to reset data information.
 * \return          \c 0 on success.
 */

int pufs_mbedtls_gcm_reset_data_ctx( mbedtls_gcm_context *ctx);


/**
 * \brief           This function initializes the specified GCM context,
 *                  to make references valid, and prepares the context
 *                  for pufs_mbedtls_gcm_setkey() or pufs_mbedtls_gcm_free().
 *
 *                  The function does not bind the GCM context to a particular
 *                  cipher, nor set the key. For this purpose, use
 *                  pugcc_mbedtls_gcm_setkey().
 *
 * \param ctx       The PUFSecurity Crypto GCM context to initialize.
 */
void pufs_mbedtls_gcm_init( mbedtls_gcm_context *ctx );

/**
 * \brief           This function associates a GCM context with a
 *                  cipher algorithm and a key.
 *

 * \param ctx       The GCM context to initialize.
 * \param cipher    The 128-bit block cipher to use.
 * \param key       The encryption key.
 * \param keybits   The key size in bits. Valid options are:
 *                  <ul><li>128 bits</li>
 *                  <li>192 bits</li>
 *                  <li>256 bits</li></ul>
 *
 * \return          \c 0 on success.
 * \return          A cipher-specific error code on failure.
 */
int pufs_mbedtls_gcm_setkey( mbedtls_gcm_context *ctx,
                             mbedtls_cipher_id_t cipher,
                             const unsigned char *key,
                             unsigned int keybits );


/**
 * \brief           This function performs GCM encryption or decryption of a buffer.
 *
 * \note            For encryption, the output buffer can be the same as the
 *                  input buffer. For decryption, the output buffer cannot be
 *                  the same as input buffer. If the buffers overlap, the output
 *                  buffer must trail at least 8 Bytes behind the input buffer.
 *
 * \warning         When this function performs a decryption, it outputs the
 *                  authentication tag and does not verify that the data is
 *                  authentic. You should use this function to perform encryption
 *                  only. For decryption, use mbedtls_gcm_auth_decrypt() instead.
 *
 * \param ctx       The GCM context to use for encryption or decryption.
 * \param mode      The operation to perform:
 *                  - #MBEDTLS_GCM_ENCRYPT to perform authenticated encryption.
 *                    The ciphertext is written to \p output and the
 *                    authentication tag is written to \p tag.
 *                  - #MBEDTLS_GCM_DECRYPT to perform decryption.
 *                    The plaintext is written to \p output and the
 *                    authentication tag is written to \p tag.
 *                    Note that this mode is not recommended, because it does
 *                    not verify the authenticity of the data. For this reason,
 *                    you should use mbedtls_gcm_auth_decrypt() instead of
 *                    calling this function in decryption mode.
 * \param length    The length of the input data, which is equal to the length
 *                  of the output data.
 * \param iv        The initialization vector.
 * \param iv_len    The length of the IV.
 * \param add       The buffer holding the additional data.
 * \param add_len   The length of the additional data.
 * \param input     The buffer holding the input data. Its size is \b length.
 * \param output    The buffer for holding the output data. It must have room
 *                  for \b length bytes.
 * \param tag_len   The length of the tag to generate.
 * \param tag       The buffer for holding the tag.
 *
 * \return          \c 0 if the encryption or decryption was performed
 *                  successfully. Note that in #MBEDTLS_GCM_DECRYPT mode,
 *                  this does not indicate that the data is authentic.
 * \return          #MBEDTLS_ERR_GCM_BAD_INPUT if the lengths are not valid.
 * \return          #MBEDTLS_ERR_GCM_HW_ACCEL_FAILED or a cipher-specific
 *                  error code if the encryption or decryption failed.
 */
int pufs_mbedtls_gcm_crypt_and_tag( mbedtls_gcm_context *ctx,
                                    int mode,
                                    size_t length,
                                    const unsigned char *iv,
                                    size_t iv_len,
                                    const unsigned char *add,
                                    size_t add_len,
                                    const unsigned char *input,
                                    unsigned char *output,
                                    size_t tag_len,
                                    unsigned char *tag );

/**
 * \brief           This function performs a GCM authenticated decryption of a
 *                  buffer.
 *
 * \note            For decryption, the output buffer cannot be the same as
 *                  input buffer. If the buffers overlap, the output buffer
 *                  must trail at least 8 Bytes behind the input buffer.
 *
 * \param ctx       The GCM context.
 * \param length    The length of the ciphertext to decrypt, which is also
 *                  the length of the decrypted plaintext.
 * \param iv        The initialization vector.
 * \param iv_len    The length of the IV.
 * \param add       The buffer holding the additional data.
 * \param add_len   The length of the additional data.
 * \param tag       The buffer holding the tag to verify.
 * \param tag_len   The length of the tag to verify.
 * \param input     The buffer holding the ciphertext. Its size is \b length.
 * \param output    The buffer for holding the decrypted plaintext. It must
 *                  have room for \b length bytes.
 *
 * \return          \c 0 if successful and authenticated.
 * \return          #MBEDTLS_ERR_GCM_AUTH_FAILED if the tag does not match.
 * \return          #MBEDTLS_ERR_GCM_BAD_INPUT if the lengths are not valid.
 * \return          #MBEDTLS_ERR_GCM_HW_ACCEL_FAILED or a cipher-specific
 *                  error code if the decryption failed.
 */
int pufs_mbedtls_gcm_auth_decrypt( mbedtls_gcm_context *ctx,
                                   size_t length,
                                   const unsigned char *iv,
                                   size_t iv_len,
                                   const unsigned char *add,
                                   size_t add_len,
                                   const unsigned char *tag,
                                   size_t tag_len,
                                   const unsigned char *input,
                                   unsigned char *output );

/**
 * \brief           This function starts a GCM encryption or decryption
 *                  operation.
 *
 * \param ctx       The GCM context.
 * \param mode      The operation to perform: #MBEDTLS_GCM_ENCRYPT or
 *                  #MBEDTLS_GCM_DECRYPT.
 * \param iv        The initialization vector.
 * \param iv_len    The length of the IV.
 * \param add       The buffer holding the additional data, or NULL
 *                  if \p add_len is 0.
 * \param add_len   The length of the additional data. If 0,
 *                  \p add is NULL.
 *
 * \return          \c 0 on success.
 */
int pufs_mbedtls_gcm_starts( mbedtls_gcm_context *ctx,
                             int mode,
                             const unsigned char *iv,
                             size_t iv_len,
                             const unsigned char *add,
                             size_t add_len );

/**
 * \brief           This function feeds an input buffer into an ongoing GCM
 *                  encryption or decryption operation.
 *
 *    `             The function expects input to be a multiple of 16
 *                  Bytes. Only the last call before calling
 *                  mbedtls_gcm_finish() can be less than 16 Bytes.
 *
 * \note            For decryption, the output buffer cannot be the same as
 *                  input buffer. If the buffers overlap, the output buffer
 *                  must trail at least 8 Bytes behind the input buffer.
 *
 * \param ctx       The GCM context.
 * \param length    The length of the input data. This must be a multiple of
 *                  16 except in the last call before mbedtls_gcm_finish().
 * \param input     The buffer holding the input data.
 * \param output    The buffer for holding the output data.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_GCM_BAD_INPUT on failure.
 */
int pufs_mbedtls_gcm_update( mbedtls_gcm_context *ctx,
                             size_t length,
                             const unsigned char *input,
                             unsigned char *output );

/**
 * \brief           This function finishes the GCM operation and generates
 *                  the authentication tag.
 *
 *                  It wraps up the GCM stream, and generates the
 *                  tag. The tag can have a maximum length of 16 Bytes.
 *
 * \param ctx       The GCM context.
 * \param tag       The buffer for holding the tag.
 * \param tag_len   The length of the tag to generate. Must be at least four.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_GCM_BAD_INPUT on failure.
 */
int pufs_mbedtls_gcm_finish( mbedtls_gcm_context *ctx,
                             unsigned char *tag,
                             size_t tag_len );

/**
 * \brief           This function clears a GCM context and the underlying
 *                  cipher sub-context.
 *
 * \param ctx       The GCM context to clear.
 */
void pufs_mbedtls_gcm_free( mbedtls_gcm_context *ctx );


#ifdef __cplusplus
}
#endif


#endif /* pufs_mbedtls_gcm.h */
