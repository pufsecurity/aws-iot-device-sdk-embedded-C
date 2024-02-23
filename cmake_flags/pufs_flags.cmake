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

# OPENSSL and MbedTLS session key log feature
# ON  : Enable log session key
# OFF : Disable log session key
set (OPENSSL_LOG_SESSION_KEY OFF)
set (MBEDTLS_LOG_SESSION_KEY OFF)

################################
# Mbedtls Levels:
# - 0 No debug
# - 1 Error
# - 2 State change
# - 3 Informational
# - 4 Verbose
###############################
set (MBEDTLS_DEBUG_LEVEL_VALUE 0)

if (OPENSSL_LOG_SESSION_KEY)
    add_definitions(-DOPENSSL_KEY_LOG)
endif()

if (MBEDTLS_LOG_SESSION_KEY)
    add_definitions(-DPUFS_MBEDTLS_KEY_CB_LOG)
endif()

if (MBEDTLS_DEBUG_LEVEL_VALUE GREATER 0)
    message ("mbedtls loglevel ${MBEDTLS_DEBUG_LEVEL_VALUE}")
    add_definitions(-DMBEDTLS_DEBUG_LOG_LEVEL=${MBEDTLS_DEBUG_LEVEL_VALUE})
endif()

# set demo log
################################
# DEMO Log Levels:
# - 0 Only demo logs
# - 1 demo + library info + function call
###############################
set (DEMO_LOG_LEVEL_VALUE  0)
add_definitions(-DDEMO_LOG_LEVEL=${DEMO_LOG_LEVEL_VALUE})



# Set PUFsecurity HW crypto
set (PUFS_HW_CRYPTO ON)
if (PUFS_HW_CRYPTO)
    add_definitions(-DPUFS_HW)

    set (PUFS_HW_TLS_CRYPTO ON)

    # Set PUFse host
    if (PUFSE_HOST)
        message("PUFSE_HOST defined !!")
        add_definitions(-DPUFSE_HOST)
    endif()


endif()
