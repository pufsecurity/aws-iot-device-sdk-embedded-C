# 1. Source
To get the source, clone from the puf-dev-pufse branch of the PUFsecurity AWS IoT Device SDK for Embedded C GitHub repository:

git clone -b puf-dev-pufse https://github.com/pufsecurity/aws-iot-device-sdk-embedded-C.git --recurse-submodules

# 2. Description #

PUFsecurity demonstrates mqtt_demo_mutual_auth example by using mbedtls and PUFsecurity hardware crypto
and [mqtt_demo_mutual_auth_pufs_hw](demos/mqtt/mqtt_demo_mutual_auth_pufs_hw) is the revised demo example.


The demo example supports two types of PUFsecurity hardware: PUFcc and PUFse EVB/FPGA, and the type of running harware to be built is configured by
the setting "PUFSE_HOST" in config.sh.

- PUFSE_HOST=no
  The demo code uses **PUFcc** crypto.
  The demo code has been verified on the Alinx AX7Z100 FPGA board with pif0a1 pufcc FPGA image.
  (Alinx AX7Z100 uses Xilinz ZynQ7000 SoC; the FPGA image is built by petalinux v2017 version.)

- PUFSE_HOST=no
  The demo code uses **PUFse EVB/FPGA**.
  When using PUFse EVB or FPGA, the PUFse device is connected to a host device via a usb cable (see below figure).
  The demo code will be executed in the host device.
  Currently, the supported OS of the host device is a linux-based OS.
  The demo code has been verified when the host device is an ubuntu 20 VM or an Alinx AX7Z100 FPGA board.
  (Note: the Alinx AX7Z100 FPGA image is built by petalinux v2021 version.)

    ```
    ----------------                ----------------
    | Host Device  |                |     PUFse    |
    | (x86 or ARM) |                |  EVB or FPGA |
    |              | <---- usb ---> |              |
    | (demo code)  |                |              |
    ----------------                ----------------

         Figure: Test architecture of using PUFse
    ```


# 3. Build Code #
# 3.1. Prerequisite #

  - Clone submodule

     ```
     ./update_submodule.sh
     ```

  - Install 'libudev' for pufse host utility
    - if running in linux VM
      ```
      sudo apt-get install libudev-dev
      ```
    - if running in the Alinx 7Z100 board, need to install libudev-dev by setting "CONFIG_libudev=y in rootfs" when building petalinux image.



## 3.2 Configuration and Options Settings ##

Before compiling, check whether the settings and options are suitable for your environment and requirements.

### 3.2.1 Configurations ###
Two files, config.sh and arm_tool_chain.cmake, are used to set configurations related to gcc version, used library paths for cross cmpilation, and used pufsecurity hareware.
See below for the details.

- [config.sh](config.sh)
  - **PUFSE_HOST**
    - YES : Build demo binary with pufse + pufse host utility if PUFS_HW_CRYPTO is set in pufsFilePaths.cmake
    - NO  : Build demo binary with pufcc if PUFS_HW_CRYPTO is set in pufsFilePaths.cmake
  - **GCC_ARM**
    - YES : Build demo image for ARM CPU system with arm cross compiler
    - NO  : Build demo image for x86 CPU system
  - **OPENSSL_ARM_PATH**
    - The precompiled openssl installed path for ARM cross-compiler
  - **MOSQUITTO_ARM_PATH*8
    - The precompiled mosquitto installed path for ARM cross-compiler

- [arm_tool_chain.cmake](cmake_flags/arm_tool_chain.make)
 - arm compiler tool cahin path : **ARM_COMPILER_TOOLCHAIN_PATH**
   - When building demo binary for pufcc use arm cross compile v6.2.1
   - When building demo binary for arm platform pufse host utility,use arm cross compile v10.2
   ```
   # Example for v6.2.1
   set (ARM_COMPILER_TOOLCHAIN_PATH /home/vagrant/tools/arm_bin_16/gcc-arm-linux-gnueabi/bin)

   # Example for v10.2.0
   set (ARM_COMPILER_TOOLCHAIN_PATH /home/vagrant/tools/gcc/gcc-linaro-10.2.1-2021.01-x86_64_arm-linux-gnueabihf/bin)
   ```

### 3.3.2 Options ###
Some options of pufsecurity demo code are listed in pufs_flags.cmake.
- [pufs_flags.cmake](cmake_flags/pufs_flags.cmake)
  - Wireshark log key options: **OPENSSL_LOG_SESSION_KEY** and **MBEDTLS_LOG_SESSION_KEY**
    - YES : the key to decrypt wireshark tls packets will be logged in file "key_log.txt".
    - NO : key won't be logged.
  - Mbedtls log level : **MBEDTLS_DEBUG_LEVEL_VALUE**
    The debug level of mbedtls logs.

    ```
    ################################
    # Mbedtls Levels:
    # - 0 No debug
    # - 1 Error
    # - 2 State change
    # - 3 Informational
    # - 4 Verbose
    ###############################
    ```

  - PUFsecurity crypto : **PUFS_HW_CRYPTO**
    - Mbedtls PUFsecurity crypto alternative: **PUFS_HW_TLS_CRYPTO**
      - Use PUFsecurity hardware crypto instead of sw crypto (OpenSSL or Mbedtls)
      - Note : when PUFS_HW_CRYPTO and PUFS_HW_TLS_CRYPTO are set as ON, need to mark "make mqtt_demo_mutual_auth_pufs" in build.sh
               Otherwise, compile error because of no pufs_xxxx functions in libmbedtls.so



# 3.3 Commands to build demo code #


   - Run Cmake config for the 1st build

     ```
     ./config.sh
     ```

   - build all libraries and demos (optional)
     ```
     cd build
     make
     ```

   - build mqtt_demo_mutual_auth* demos.
     ```
     ./build.sh
     ```

   - After compilation successfully, the demo code binary and necessary certs , library (.so) and necessary certs will be generated in the build folder.
     - demo example and certs: build/bin
     - libraries: build/lib
     Both bin and lib folders should be copied to running target.

## 3.4. Cross compilation ##
When the target running environment is **Alinx AX7Z100 FPGA board (ZYNQ 7000 SoC)**, arm cross compilation tool is used to build code in x86 system.
The library information required for the cross-compilation is listed below.

- GCC and glibc versions
  - When the FPGA image is built by using petalinux v2017 version (image for pufcc pif0a1 version)
    - GCC : arm-linux-gnueabihf-gcc (Linaro GCC Snapshot 6.2-2016.11) 6.2.1 20161114
            Can be downloaded from [linaro arm-linux-gnueabihf 6.2.1](https://releases.linaro.org/components/toolchain/binaries/6.2-2016.11/arm-linux-gnueabihf/gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf.tar.xz)
    - glibc : libc-2.23

  - When the FPGA image is built by using petalinux v2021 version
    - GCC : arm-xilinx-linux-gnueabi
      - alternative : arm-linux-gnueabihf-gcc (linaro arm-linux-gnueabihf 10.2.1)
      - The alternative arm cross compiler can be downloaded from [linaro arm-linux-gnueabihf 10.2.1](https://snapshots.linaro.org/components/toolchain/binaries/10.2-2021.01-3/arm-linux-gnueabihf/gcc-linaro-10.2.1-2021.01-x86_64_arm-linux-gnueabihf.tar.xz)

    - glibc : libc-2.28
    - Note: This image is used when running pufse host utility in the Alinx 7Z100 fpga board. When running the pufse host utility, the pufse EVB or FPGA boards must be connected to the 7Z100 FPGA boards.

- Openssl 1.1.0k
  The openssl version requirement of aws iot sdk should be 1.1.0 or later. => Openssl 1.1.0k is used in our test environment.

  - Steps for cross compiling openssl library:
    ```
    # Download
    wget https://www.openssl.org/source/old/1.1.0/openssl-1.1.0k.tar.gz

    # untar openssl
    tar xvfz openssl-1.1.0k.tar.gz

    # Configure openssl
    # set cross-compile-prefix and installed prefix folder paths
    # Example :
    # cross-compile-prefix=/home/vagrant/tools/arm_ubun_16/gcc-arm-linux-gnueabi/bin/arm-linux-gnueabihf-
    # prefix=/home/vagrant/projects/awsiot/openssl/bin/openssl_1_1_1k_arm
    cd openssl_1.1.1k
    ./Configure linux-generic32 --cross-compile-prefix=/home/vagrant/tools/arm_ubun_16/gcc-arm-linux-gnueabi/bin/arm-linux-gnueabihf- \
      -shared --prefix=/home/vagrant/projects/awsiot/openssl/bin/openssl_1_1_1k_arm

    # Make and install library to the configured prefix folder
    make
    make install
    ```

  - file tree of the prefix folder
    ```
    $ tree -L 2
    .
    ├── bin
    │   ├── c_rehash
    │   └── openssl
    ├── include
    │   └── openssl
    ├── lib
    │   ├── engines-1.1
    │   ├── libcrypto.a
    │   ├── libcrypto.so -> libcrypto.so.1.1
    │   ├── libcrypto.so.1.1
    │   ├── libssl.a
    │   ├── libssl.so -> libssl.so.1.1
    │   ├── libssl.so.1.1
    │   └── pkgconfig
    ├── share
    │   ├── doc
    │   └── man
    └── ssl
        ├── certs
        ├── ct_log_list.cnf
        ├── ct_log_list.cnf.dist
        ├── misc
        ├── openssl.cnf
        ├── openssl.cnf.dist
        └── private

    ```

- Mosquitt (use version 1.6.14)

  - Download
    ```
    wget https://mosquitto.org/files/source/mosquitto-1.6.14.tar.gz
    ```
  - untar the downloaded file
    ```
    tar xvfz mosquitto-1.6.14.tar.gz
    ```

  - Enter the untared mosquitto folder
    cd mosquitto-1.6.14

  - Prepare the following build script to compile (make options:not build openssl, use cross compile)
    The GCC_PATH should be set the GCC bin folder of your environment.
    The default installed prefix folder is set to $ROOT_DIR/bin.
    ```
    GCC_PATH=/home/vagrant/tools/arm_bin_16/gcc-arm-linux-gnueabi/bin
    ROOT_DIR=$PWD
    #arm-linux-gnueabihf-gcc
    export PATH=$GCC_PATH:$OPENSSL_INCLUDE_DIR:$PATH

    make CROSS_COMPILE=arm-linux-gnueabihf- CC=gcc prefix=$ROOT_DIR/bin WITH_TLS=no WITH_DOCS=no
    make install CROSS_COMPILE=arm-linux-gnueabihf- CC=gcc prefix=$ROOT_DIR/bin WITH_TLS=no WITH_DOCS=no
    ```
    sometimes symbolic link creation is failed, mark the ln xxx in corresponding makefile

  - The corresponding library and include file are in the set prefix folder
    ```
    vagrant@ubuntu20-puf-dev:/vagrant/share/Load/FY112/aws/sdk/mosquitto-1.6.14_arm/bin$ tree -L 2
    .
    ├── bin
    │   ├── mosquitto_pub
    │   ├── mosquitto_rr
    │   └── mosquitto_sub
    ├── include
    │   ├── mosquitto.h
    │   ├── mosquitto_broker.h
    │   ├── mosquitto_plugin.h
    │   ├── mosquittopp.h
    │   └── mqtt_protocol.h
    ├── lib
    │   ├── libmosquitto.so.1
    │   ├── libmosquittopp.so.1
    │   └── pkgconfig
    └── sbin
        └── mosquitto
    ```



# 4. Execution
- cp build/bin and build/lib to the running target
  - The above command can done by cp.sh with necessary modifications.
    -  Revise the destination address and port in cp.sh,
    -  execute "./cp.sh" to tar bin and lib folders to bin.tgz and copy the bin.tgz to the running target.
    - Note: need to untar the bin.tgz before running

- ssh to the running target and enter the copied bin folder
  - Modify the CERT_PATH, CLIENT_ID, CLIENT_CERT in the run.sh to the device which is registered in the AWS IoT Core
    Example:
    ```
    CERT_PATH=$PWD/certs-puf/device/c-test-thing-uid
    CLIENT_ID=puf_4768418ee32618c6ddce00bbcb67f896c3fc0087639219c7ca3240949be47a37
    CLIENT_CERT=pufs_4768418e-pubkey.pem.crt

    ```

  - Set the library path by the below command.
    ```
    source ./env.sh
    ```

  - Then executing mqtt_demo_mutual_auth_pufs_hw with the device uid and device certificate set in the run.sh.
    ```
    ./run.sh
    ```
# 5. LICENSE
  - LICENSE for Source code modified or provided by PUFsecurity: MIT, BSD 3-Clause, or Apache-2.0
    See [LICENSE_PUFsecurity.txt](LICENSE_PUFsecurity.txt) and [libraries/3rdparty/pufs/LICENSE.txt](libraries/3rdparty/pufs/LICENSE.txt)
