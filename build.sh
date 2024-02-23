#!/bin/bash

# Build mqtt_demo_mutual_auth* demos
# When PUFS_HW_CRYPTO is ON, need to mark 'make mqtt_demo_mutual_auth_pufs' to
# avoid build failure because of no pufs-related alternative functions.

cd build

# Build original mutual auth demo (using OpenSSL)
# ----------------------------------------------
make mqtt_demo_mutual_auth

# Build mqtt_demo_mutual_auth_pufs when using mbedtls to establish TLS connection
# ----------------------------------------------
#make mqtt_demo_mutual_auth_pufs

# Build mqtt_demo_mutual_auth_pufs when using mbedtls to establish TLS connection
# with PUFsecurity HW
# ----------------------------------------------
make mqtt_demo_mutual_auth_pufs_hw
