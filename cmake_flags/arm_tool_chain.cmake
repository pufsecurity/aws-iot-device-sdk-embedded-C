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


#set (ARM_COMPILER_TOOLCHAIN_PATH /usr/bin)


# To do: move ARM_COMPILER_TOOLCHAIN_PATH to the config file!!
if (PUFSE_HOST)
    set (ARM_COMPILER_TOOLCHAIN_PATH /home/vagrant/tools/gcc/gcc-linaro-10.2.1-2021.01-x86_64_arm-linux-gnueabihf/bin)
else()
    set (ARM_COMPILER_TOOLCHAIN_PATH /home/vagrant/tools/arm_bin_16/gcc-arm-linux-gnueabi/bin)
endif()
set (CMAKE_C_COMPILER       ${ARM_COMPILER_TOOLCHAIN_PATH}/arm-linux-gnueabihf-gcc)


# OpenSSL path
set ( OPENSSL_INCLUDE_DIR     ${OPENSLL_LIB_PATH}/include)
set ( OPENSSL_CRYPTO_LIBRARY  ${OPENSLL_LIB_PATH}/lib/libcrypto.so.1.1)
set ( OPENSSL_SSL_LIBRARY     ${OPENSLL_LIB_PATH}/lib/libssl.so.1.1)

# GLIBC
set (ARM_COMPILER_LIBC_PATH /vagrant/share/tools/arm_ubun_16/gcc-arm-linux-gnueabi/arm-linux-gnueabihf/libc)
set(ENV{LD_LIBRARY_PATH}  "${ARM_COMPILER_LIBC_PATH}/lib")

# MOSQUITTO
# MOSQUITTO path /home/vagrant/share/Load/FY112/aws/sdk/mosquitto-1.6.14_arm/bin/
set ( MOSQUITTO_LIBRARY       ${MOSQUITTO_ARM_PATH}/bin/lib/libmosquitto.so.1)
set ( MOSQUITTO_INCLUDE_DIR   ${MOSQUITTO_ARM_PATH}/bin/include)
