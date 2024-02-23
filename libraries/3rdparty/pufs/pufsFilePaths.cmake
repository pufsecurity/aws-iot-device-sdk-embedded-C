#############################################################################
#
# Copyright 2023-2024, PUFsecurity
#
# It is licensed under the BSD 3-Clause license; you may not use this file
# except in compliance with the License.
#
# You may obtain a copy of the License at:
#  https://opensource.org/licenses/BSD-3-Clause
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#############################################################################

#############################################################################
# File Description
# This file is to add pufsecurity related include directories into variables
# Some useful macro are also defined here (to do: move to another cmake file)
#############################################################################

# Macro utility to apply patch
macro( patch_mbedtls dst_repo_path patch_file_path )

    set(path ${patch_file_path})
    cmake_path(GET path PARENT_PATH src_dir)
    cmake_path(GET path FILENAME file_name)

    #check if patch file exist
    if ( NOT EXISTS ${dst_repo_path}/${file_name} )
        file(COPY ${patch_file_path}
                 DESTINATION ${dst_repo_path})


        execute_process( COMMAND ${GIT_EXECUTABLE} apply ${dst_repo_path}/${file_name}
                         WORKING_DIRECTORY ${dst_repo_path}
                         RESULT_VARIABLE PATCH_APPLY_RESULT )
        if ( NOT ${PATCH_APPLY_RESULT} STREQUAL "0" )
            message( FATAL_ERROR "Failed to apply patch to ${dst_repo_path}." )
        else()
            message( "Apply patch ${patch_file_path} to ${dst_repo_path} successfull." )
        endif()

    else()
        message("${dst_repo_path}/${file_name} exist!! no need patched!!")
    endif()

endmacro()


# PUFsecurity HW Library
if (PUFSE_HOST)

    set( PUFS_PUFSE_HOST_LIB_DIR
             ${3RDPARTY_DIR}/pufs/pufse_host_lib )

    set( PUFS_PUFSE_HOST_LIB_INCLUDE_DIR
         ${PUFS_PUFSE_HOST_LIB_DIR}/include)

    set( PUFS_PUFSE_HOST_LIB_PUFSE_DIR
         ${PUFS_PUFSE_HOST_LIB_INCLUDE_DIR}/pufse)

    set( PUFS_PUFSE_HOST_LIB_HIDAPI_DIR
         ${PUFS_PUFSE_HOST_LIB_INCLUDE_DIR}/hidapi)

    set( PUFS_HW_CRYPTO_INCLUDE_DIRS
         #${PUFS_PUFSE_HOST_LIB_PUFSE_DIR}/hal
         ${PUFS_PUFSE_HOST_LIB_PUFSE_DIR}/inc
         )

    if (PUFS_HW_TLS_CRYPTO)
        set( PUFS_HW_CRYPTO_INCLUDE_DIRS
             ${PUFS_HW_CRYPTO_INCLUDE_DIRS}
             ${PUFS_PUFSE_HOST_LIB_PUFSE_DIR}/hal
             ${PUFS_PUFSE_HOST_LIB_PUFSE_DIR}/src_inc
            )
    endif()

    set( PUFS_HW_CRYPTO_LIB_DIR
         ${3RDPARTY_DIR}/pufs/pufse_host_lib/lib )

    if (GCC_ARM)
        set( PUFS_HW_CRYPTO_LIB_UDEV_DIR
            ${3RDPARTY_DIR}/pufs/pufse_host_lib//bsp_arm/lib_udev )
    endif()


else()

    set( PUFS_HW_CRYPTO_INCLUDE_DIRS
         ${3RDPARTY_DIR}/pufs/pufcc/include
         ${3RDPARTY_DIR}/pufs/pufcc/include/internal )

    set( PUFS_HW_CRYPTO_LIB_DIR
         ${3RDPARTY_DIR}/pufs/pufcc/lib )

endif(PUFSE_HOST)


# Pufsecurity Mbedtls files
set( PUFS_HW_MBEDTLS_DIR  ${3RDPARTY_DIR}/pufs/mbedtls )

if (PUFS_HW_TLS_CRYPTO)

    if (PUFSE_HOST)

        # pufse host library
        set(PUFS_HW_MBEDTLS_CRYPTO_ALT_DIR
            ${ROOT_DIR}/libraries/3rdparty/pufs/mbedtls/pufse_host_alt)

    else()

        # PUFCC library
        set(PUFS_HW_MBEDTLS_CRYPTO_ALT_DIR
            ${ROOT_DIR}/libraries/3rdparty/pufs/mbedtls/pufcc_alt)

    endif(PUFSE_HOST)

    set(PUFS_HW_MBEDTLS_CRYPTO_ALT_SRC_DIR
           ${PUFS_HW_MBEDTLS_CRYPTO_ALT_DIR}/src)

    set(PUFS_HW_MBEDTLS_CRYPTO_ALT_INC_DIR
           ${PUFS_HW_MBEDTLS_CRYPTO_ALT_DIR}/include)


endif(PUFS_HW_TLS_CRYPTO)