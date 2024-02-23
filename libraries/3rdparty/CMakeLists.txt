if(${BUILD_TESTS})
    add_library(cmock STATIC
        "${ROOT_DIR}/libraries/3rdparty/CMock/src/cmock.c"
    )

    set_target_properties(cmock PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        POSITION_INDEPENDENT_CODE ON
        COMPILE_FLAGS "-Og"
    )

    add_library(unity STATIC
        "${3RDPARTY_DIR}/CMock/vendor/unity/src/unity.c"
        "${3RDPARTY_DIR}/CMock/vendor/unity/extras/fixture/src/unity_fixture.c"
        "${3RDPARTY_DIR}/CMock/vendor/unity/extras/memory/src/unity_memory.c"
    )
    set_target_properties(unity PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        POSITION_INDEPENDENT_CODE ON
    )

    target_include_directories(cmock PUBLIC
        ${ROOT_DIR}/libraries/3rdparty/CMock/src
        ${ROOT_DIR}/libraries/3rdparty/CMock/vendor/unity/src/
        ${ROOT_DIR}/libraries/3rdparty/CMock/examples
    )

    target_link_libraries(cmock unity)
endif()

add_library(tinycbor
    "${ROOT_DIR}/libraries/3rdparty/tinycbor/src/cborpretty.c"
    "${ROOT_DIR}/libraries/3rdparty/tinycbor/src/cborpretty_stdio.c"
    "${ROOT_DIR}/libraries/3rdparty/tinycbor/src/cborencoder.c"
    "${ROOT_DIR}/libraries/3rdparty/tinycbor/src/cborencoder_close_container_checked.c"
    "${ROOT_DIR}/libraries/3rdparty/tinycbor/src/cborerrorstrings.c"
    "${ROOT_DIR}/libraries/3rdparty/tinycbor/src/cborparser.c"
    "${ROOT_DIR}/libraries/3rdparty/tinycbor/src/cborparser_dup_string.c"
)

set_target_properties(tinycbor PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    POSITION_INDEPENDENT_CODE ON
)

# Use C99 for tinycbor as it is incompatible with C90
if(CMAKE_C_STANDARD LESS 99)
    set_target_properties(tinycbor PROPERTIES C_STANDARD 99)
endif()

target_include_directories(tinycbor PUBLIC
    "${ROOT_DIR}/libraries/3rdparty/tinycbor/src"
)


file(GLOB MBEDTLS_FILES CONFIGURE_DEPENDS "${ROOT_DIR}/libraries/3rdparty/mbedtls/library/*.c")

# PUFS +++
if (PUFS_HW_CRYPTO)
    # include pufsecurity file paths
    include( ${3RDPARTY_DIR}/pufs/pufsFilePaths.cmake )
endif ()

if (PUFS_HW_TLS_CRYPTO)

    file(GLOB MBEDTLS_PUFS_ALT_FILES CONFIGURE_DEPENDS
         "${PUFS_HW_MBEDTLS_CRYPTO_ALT_SRC_DIR}/sha256_alt.c"
         "${PUFS_HW_MBEDTLS_CRYPTO_ALT_SRC_DIR}/pufs_mbedtls_sha256.c"
         "${PUFS_HW_MBEDTLS_CRYPTO_ALT_SRC_DIR}/ecdsa_alt.c"
         "${PUFS_HW_MBEDTLS_CRYPTO_ALT_SRC_DIR}/pufs_mbedtls_ecdsa.c"
         "${PUFS_HW_MBEDTLS_CRYPTO_ALT_SRC_DIR}/ecdh_alt.c"
         "${PUFS_HW_MBEDTLS_CRYPTO_ALT_SRC_DIR}/pufs_mbedtls_ecdh.c"
         "${PUFS_HW_MBEDTLS_CRYPTO_ALT_SRC_DIR}/gcm_alt.c"
         "${PUFS_HW_MBEDTLS_CRYPTO_ALT_SRC_DIR}/pufs_mbedtls_gcm.c"
    )

    add_library(mbedtls
        ${MBEDTLS_FILES}
        ${MBEDTLS_PUFS_ALT_FILES}
    )

else()
# PUFS ---
add_library(mbedtls
    ${MBEDTLS_FILES}
)

# PUFS +++
endif(PUFS_HW_TLS_CRYPTO)
# PUFS ---

set_target_properties(mbedtls PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    POSITION_INDEPENDENT_CODE ON
)

# PUFS +++

if (PUFS_HW_CRYPTO)

    if (PUFSE_HOST)
        add_library(pufse_host SHARED IMPORTED GLOBAL)

        if (GCC_ARM)

            set( PUFSE_HOST_LIB_PATH
                    ${PUFS_HW_CRYPTO_LIB_DIR}/libpufse_arm.so)

            # Cross compiler need libudev.so
            add_library(udev_arm SHARED IMPORTED GLOBAL)
            set_target_properties(udev_arm PROPERTIES IMPORTED_LOCATION
                                  "${PUFS_HW_CRYPTO_LIB_UDEV_DIR}/libudev.so")
            set_target_properties(udev_arm PROPERTIES LINKER_LANGUAGE C)

        else()

            set( PUFSE_HOST_LIB_PATH
                    ${PUFS_HW_CRYPTO_LIB_DIR}/libpufse_x86.so)

        endif()


        # Specify the full path of the import library
        set_target_properties(pufse_host PROPERTIES IMPORTED_LOCATION
                                 ${PUFSE_HOST_LIB_PATH})

        # Copy libpufse
        if (NOT EXISTS ${CMAKE_BINARY_DIR}/lib/)
            file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/lib/)
        endif()

        file(COPY_FILE ${PUFSE_HOST_LIB_PATH}
                    ${CMAKE_BINARY_DIR}/lib/libpufse.so)


        set_target_properties(pufse_host PROPERTIES LINKER_LANGUAGE C)

    else()
        add_library(pufcc SHARED IMPORTED GLOBAL)

        # Specify the full path of the import library
        set_target_properties(pufcc PROPERTIES IMPORTED_LOCATION "${PUFS_HW_CRYPTO_LIB_DIR}/libpufcc.so")


        file(COPY "${PUFS_HW_CRYPTO_LIB_DIR}/libpufcc.so"
             DESTINATION ${CMAKE_BINARY_DIR}/lib)

        set_target_properties(pufcc PROPERTIES LINKER_LANGUAGE C)
   endif()

endif(PUFS_HW_CRYPTO)
# PUFS ---

# Use C99 for mbedtls as v2.26.0 is incompatible with C90
if(CMAKE_C_STANDARD LESS 99)
    set_target_properties(mbedtls PROPERTIES C_STANDARD 99)
endif()



# PUFS +++
if (PUFS_HW_CRYPTO)
    if (PUFS_HW_TLS_CRYPTO)

        target_include_directories(mbedtls
            PUBLIC
                "${ROOT_DIR}/libraries/3rdparty/mbedtls/include"
                "${ROOT_DIR}/platform/posix/include"
                "${ROOT_DIR}/libraries/3rdparty/pufs/mbedtls/config"
                "${ROOT_DIR}/libraries/3rdparty/pufs/pufs_util/source"
                "${PUFS_HW_MBEDTLS_CRYPTO_ALT_INC_DIR}"
                "${PUFS_HW_CRYPTO_INCLUDE_DIRS}"
        )

        if (PUFSE_HOST)
            # Patch mbedtls patch
            patch_mbedtls( ${ROOT_DIR}/libraries/3rdparty/mbedtls
                            ${PUFS_HW_MBEDTLS_CRYPTO_ALT_DIR}/patch/mbedtls_pufse.patch)
        endif(PUFSE_HOST)

    else(PUFS_HW_TLS_CRYPTO)

        target_include_directories(mbedtls
            PUBLIC
                "${ROOT_DIR}/libraries/3rdparty/mbedtls/include"
                "${ROOT_DIR}/platform/posix/include"
                "${ROOT_DIR}/libraries/3rdparty/pufs/mbedtls/config"
        )

    endif(PUFS_HW_TLS_CRYPTO)

else()
# PUF ---

target_include_directories(mbedtls
    PUBLIC
        "${ROOT_DIR}/libraries/3rdparty/mbedtls/include"
        "${ROOT_DIR}/platform/posix/include"
)

# PUFS +++
endif (PUFS_HW_CRYPTO)
# PUFS ---

# PUFS +++
# Use PUFS pufs_mbedtls_config.h
if (PUFS_HW_CRYPTO)
    if (PUFS_HW_TLS_CRYPTO)
        if (PUFSE_HOST)
        target_compile_definitions(
            mbedtls
            PUBLIC
                -DMBEDTLS_CONFIG_FILE="pufs_mbedtls_config.h"
                -DPUFS_TLS_CRYPTO_ALT
                -DPUFSE_HOST
        )

        else()
        target_compile_definitions(
            mbedtls
            PUBLIC
                -DMBEDTLS_CONFIG_FILE="pufs_mbedtls_config.h"
                -DPUFS_TLS_CRYPTO_ALT
        )
        endif(PUFSE_HOST)

    else()
        target_compile_definitions(
            mbedtls
            PUBLIC
                -DMBEDTLS_CONFIG_FILE="pufs_mbedtls_config.h"
        )
    endif()
else()
# PUFS ---
target_compile_definitions(
    mbedtls
    PUBLIC
        -DMBEDTLS_CONFIG_FILE="mbedtls_config.h"
)
# PUFS +++
endif(PUFS_HW_CRYPTO)
# PUFS ---

set_source_files_properties(
    ${MBEDTLS_FILES}
    PROPERTIES COMPILE_FLAGS
    "-Wno-pedantic"
)
