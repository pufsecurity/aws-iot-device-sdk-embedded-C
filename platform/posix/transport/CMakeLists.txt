# Include filepaths for source and include.
include( ${PLATFORM_DIR}/posix/posixFilePaths.cmake )


# PUFS +++
if (PUFS_HW_CRYPTO)
    include ( ${3RDPARTY_DIR}/pufs/pufs_util/pufsUtilFilePaths.cmake )
endif()
# PUFS ---
set( TRANSPORT_INTERFACE_INCLUDE_DIR
     ${MODULES_DIR}/standard/coreMQTT/source/interface )

# Create target for sockets utility.
add_library( sockets_posix
                ${SOCKETS_SOURCES} )

target_include_directories( sockets_posix
                            PUBLIC
                                ${COMMON_TRANSPORT_INCLUDE_PUBLIC_DIRS}
                                ${LOGGING_INCLUDE_DIRS}
                                ${TRANSPORT_INTERFACE_INCLUDE_DIR} )

# Create target for plaintext transport.
add_library( plaintext_posix
             ${PLAINTEXT_TRANSPORT_SOURCES} )

target_link_libraries( plaintext_posix
                       PUBLIC
                           sockets_posix )

# Create target for POSIX implementation of OpenSSL.
add_library( openssl_posix
                ${OPENSSL_TRANSPORT_SOURCES} )

# PUFS +++
if (GCC_ARM)
    target_include_directories( openssl_posix
                                PUBLIC
                                    ${OPENSSL_INCLUDE_DIR}
    )
endif ()
# PUFS ---

target_link_libraries( openssl_posix
                       PUBLIC
                          sockets_posix
                          # This variable is set by the built-in FindOpenSSL.cmake
                          # and contains the path to the actual library.
                          ${OPENSSL_LIBRARIES}
                       PRIVATE
                          # SSL uses Threads and on some platforms require
                          # explicit linking.
                          Threads::Threads
                          # SSL uses Dynamic Loading and on some platforms
                          # requires explicit linking.
                          ${CMAKE_DL_LIBS} )

# Set path to corePKCS11 and it's third party libraries.
set(COREPKCS11_LOCATION "${CMAKE_SOURCE_DIR}/libraries/standard/corePKCS11")
set(CORE_PKCS11_3RDPARTY_LOCATION "${COREPKCS11_LOCATION}/source/dependency/3rdparty")

# Include PKCS #11 library's source and header path variables.
include( ${COREPKCS11_LOCATION}/pkcsFilePaths.cmake )

list(APPEND PKCS_SOURCES
    "${COREPKCS11_LOCATION}/source/portable/os/posix/core_pkcs11_pal.c"
    "${COREPKCS11_LOCATION}/source/portable/os/core_pkcs11_pal_utils.c"
    "${CORE_PKCS11_3RDPARTY_LOCATION}/mbedtls_utils/mbedtls_utils.c"
)

# Create target for POSIX implementation of MbedTLS transport with PKCS #11.
add_library( transport_mbedtls_pkcs11_posix
                ${MBEDTLS_PKCS11_TRANSPORT_SOURCES}
                ${PKCS_SOURCES} )

target_link_libraries( transport_mbedtls_pkcs11_posix
                       PRIVATE
                          mbedtls )

target_include_directories(
    transport_mbedtls_pkcs11_posix
    PUBLIC
        ${COMMON_TRANSPORT_INCLUDE_PUBLIC_DIRS}
        ${LOGGING_INCLUDE_DIRS}
        ${TRANSPORT_INTERFACE_INCLUDE_DIR}
        ${PKCS_INCLUDE_PUBLIC_DIRS}
        "${COREPKCS11_LOCATION}/source/portable/os"
        ${CORE_PKCS11_3RDPARTY_LOCATION}/pkcs11
        ${DEMOS_DIR}/pkcs11/common/include
    PRIVATE
        ${CORE_PKCS11_3RDPARTY_LOCATION}/mbedtls_utils
)

# PUF +++
if (PUFS_MODIFY)
    # Create target for PUFSecurity POSIX implementation of MbedTLS transport.
    add_library( transport_pufs_mbedtls_posix
                     ${PUFS_MBEDTLS_TRANSPORT_SOURCES})

    target_link_libraries( transport_pufs_mbedtls_posix
                           PRIVATE
                              mbedtls )

    target_include_directories(
        transport_pufs_mbedtls_posix
        PUBLIC
            ${COMMON_TRANSPORT_INCLUDE_PUBLIC_DIRS}
            ${LOGGING_INCLUDE_DIRS}
            ${TRANSPORT_INTERFACE_INCLUDE_DIR}
        PRIVATE
            ${CORE_PKCS11_3RDPARTY_LOCATION}/mbedtls_utils
    )
endif(PUFS_MODIFY)

if (PUFS_HW_CRYPTO)
    # Create target for PUFSecurity POSIX implementation of MbedTLS transport.
    add_library( transport_pufs_hw_mbedtls_posix
                     ${PUFS_HW_MBEDTLS_TRANSPORT_SOURCES}
                     ${PUFS_HW_MBEDTLS_SOURCES})

    if (PUFSE_HOST)

        target_link_libraries( transport_pufs_hw_mbedtls_posix
                               PRIVATE
                                  mbedtls
                                  pufse_host)

    else(PUFSE_HOST)

        target_link_libraries( transport_pufs_hw_mbedtls_posix
                               PRIVATE
                                  mbedtls
                                  pufcc)

    endif(PUFSE_HOST)

    target_include_directories(
        transport_pufs_hw_mbedtls_posix
        PUBLIC
            ${COMMON_TRANSPORT_INCLUDE_PUBLIC_DIRS}
            ${LOGGING_INCLUDE_DIRS}
            ${TRANSPORT_INTERFACE_INCLUDE_DIR}
        PRIVATE
            ${CORE_PKCS11_3RDPARTY_LOCATION}/mbedtls_utils
            ${PUFS_HW_CRYPTO_INCLUDE_DIRS}
            ${PUFS_HW_MBEDTLS_DIR}
            ${PUFS_UTIL_INCLUDE_PUBLIC_DIRS}
    )
endif()
# PUF ---

# Install transport implementations as both shared and static libraries.
if(INSTALL_PLATFORM_ABSTRACTIONS)
    install(TARGETS
      openssl_posix
      plaintext_posix
      sockets_posix
      transport_mbedtls_pkcs11_posix
      LIBRARY DESTINATION "${CSDK_LIB_INSTALL_PATH}"
      ARCHIVE DESTINATION "${CSDK_LIB_INSTALL_PATH}")

    # PUFS +++
    # Install pufsecurity mbedtls transport implementations
    if (PUFS_MODIFY)
        install(TARGETS
            transport_pufs_mbedtls_posix
            LIBRARY DESTINATION "${CSDK_LIB_INSTALL_PATH}"
            ARCHIVE DESTINATION "${CSDK_LIB_INSTALL_PATH}")
    endif()

    # Install pufsecurity mbedtls transport implementations
    if (PUFS_HW_CRYPTO)
        install(TARGETS
            transport_pufs_hw_mbedtls_posix
            LIBRARY DESTINATION "${CSDK_LIB_INSTALL_PATH}"
            ARCHIVE DESTINATION "${CSDK_LIB_INSTALL_PATH}")
    endif()
    # PUFS ---

endif()
