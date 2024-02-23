#!/bin/bash
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


######################################################################################
# 1. Build Command for MQTT Mutual demo
#
#     cmake -S . -Bbuild -DAWS_IOT_ENDPOINT="<your-aws-iot-endpoint>" -DCLIENT_CERT_PATH="<your-client-certificate-path>" \
#                -DCLIENT_PRIVATE_KEY_PATH="<your-client-private-key-path>"
#
#
# 2. Build Command for AWS IoT Fleet Provisioning demo
#
#   cmake -S . -Bbuild -DAWS_IOT_ENDPOINT="<your-aws-iot-endpoint>" -DROOT_CA_CERT_PATH="<your-path-to-amazon-root-ca>" \
#              -DCLAIM_CERT_PATH="<your-claim-certificate-path>" -DCLAIM_PRIVATE_KEY_PATH="<your-claim-private-key-path>" \
#              -DPROVISIONING_TEMPLATE_NAME="<your-template-name>" -DDEVICE_SERIAL_NUMBER="<your-serial-number>"
#
#
# 3 . How to get endpoint (need to install aws iot sdk)
#
#      aws iot describe-endpoint --endpoint-type iot:Data-ATS
#
#     Note: Current used endpointAddress is as below
#           "endpointAddress": "a1yej2tjsft4ux-ats.iot.ap-southeast-2.amazonaws.com"
#
######################################################################################

# Variable Setting
ROOT_DIR=$PWD
EP=a1yej2tjsft4ux-ats.iot.ap-southeast-2.amazonaws.com
#SERVER_HOST=$EP
#BROKER_ENDPOINT=$EP
BROKER_ENDPOINT=localhost
SERVER_HOST=localhost
DEV_SN=12345678


# PUFSE_HOST (YES or NO)
PUFSE_HOST=YES
#PUFSE_HOST=NO

# Cross Compiler (YES or NO)
#GCC_ARM=NO
GCC_ARM=YES

# OpenSSL 1_1_1_1k ARM version path
OPENSSL_ARM_PATH=/vagrant/share/Load/FY112/aws/sdk/openssl_1_1_1k_arm

# mosquitto-1.6.14 ARM Version Path
MOSQUITTO_ARM_PATH=/vagrant/share/Load/FY112/aws/sdk/mosquitto-1.6.14_arm

# Folder setting
#CERT_DIR=$ROOT_DIR/certs-puf
CERT_DIR=certs-puf
DEVICE_DIR=$CERT_DIR/device
ROOT_CA_DIR=$CERT_DIR/RootCA
AWS_CA=$ROOT_CA_DIR/aws
PUFS_CA=$ROOT_CA_DIR/pufs

PUFS_CA_THING=1


if [[ "PUFS_CA_THING" -eq 1 ]]; then

    KEY_DIR=$DEVICE_DIR/c-test-thing-puf
    CLIENT_CERT_PATH=$KEY_DIR/deviceCert.crt
    PRIV_KEY_PATH=$KEY_DIR/deviceCert.key
    THING_NAME=c-test-iot-device-puf

    # Root cert use amazon for fleet provisiong test
    ROOT_CERT_PATH=$AWS_CA/AmazonRootCA1.pem


else # use

    KEY_DIR=$DEVICE_DIR/c-test-thing
    CLIENT_CERT_PATH=$KEY_DIR/c-test-thing-certificate.pem.crt
    PRIV_KEY_PATH=$KEY_DIR/c-test-thing-private.pem.key
    THING_NAME=c-test-iot-device

    ROOT_CERT_PATH=$AWS_CA/AmazonRootCA1.pem

fi

if [[ "$GCC_ARM" = "YES" ]]; then
    BUILD_APPEND=" -DGCC_ARM=YES -DOPENSLL_LIB_PATH=$OPENSSL_ARM_PATH -DMOSQUITTO_ARM_PATH=$MOSQUITTO_ARM_PATH "
else
    BUILD_APPEND=""
fi


if [[ "$PUFSE_HOST" = "YES" ]]; then
    BUILD_APPEND+=" -DPUFSE_HOST=YES "
fi

DEV_CMD="-Bbuild -DAWS_IOT_ENDPOINT=$EP -DCLIENT_CERT_PATH=$CLIENT_CERT_PATH -DCLIENT_PRIVATE_KEY_PATH=$PRIV_KEY_PATH"
NORMAL_CMD=" -Bbuild \
               -DAWS_IOT_ENDPOINT=$EP -DCLIENT_CERT_PATH=$CLIENT_CERT_PATH \
               -DCLIENT_PRIVATE_KEY_PATH=$PRIV_KEY_PATH \
               -DSERVER_HOST=$SERVER_HOST -DBROKER_ENDPOINT=$BROKER_ENDPOINT \
               -DROOT_CA_CERT_PATH=$ROOT_CERT_PATH -DTHING_NAME=$THING_NAME \
               -DDEVICE_SERIAL_NUMBER=$DEV_SN"



build_device_cmd(){

    echo "cmd : "
    echo "cmake -S . -Bbuild -DAWS_IOT_ENDPOINT=$EP -DCLIENT_CERT_PATH=$CLIENT_CERT_PATH -DCLIENT_PRIVATE_KEY_PATH=$PRIV_KEY_PATH "
    echo


    echo "===================================================="


    cmake -S . $DEV_CMD $BUILD_APPEND

<<comment
    cmake -S . -Bbuild -DAWS_IOT_ENDPOINT=$EP -DCLIENT_CERT_PATH=$CLIENT_CERT_PATH -DCLIENT_PRIVATE_KEY_PATH=$PRIV_KEY_PATH
comment
}


build_normal_case_cmd(){

    echo "
    cmake -S . -Bbuild \
               -DAWS_IOT_ENDPOINT=$EP -DCLIENT_CERT_PATH=$CLIENT_CERT_PATH \
               -DCLIENT_PRIVATE_KEY_PATH=$PRIV_KEY_PATH \
               -DSERVER_HOST=$SERVER_HOST -DBROKER_ENDPOINT=$BROKER_ENDPOINT \
               -DROOT_CA_CERT_PATH=$ROOT_CERT_PATH -DTHING_NAME=$THING_NAME \
               -DDEVICE_SERIAL_NUMBER=$DEV_SN
    "


    echo "===================================================="


    cmake -S . $NORMAL_CMD $BUILD_APPEND

 <<comment
    cmake -S . -Bbuild \
               -DAWS_IOT_ENDPOINT=$EP -DCLIENT_CERT_PATH=$CLIENT_CERT_PATH \
               -DCLIENT_PRIVATE_KEY_PATH=$PRIV_KEY_PATH \
               -DSERVER_HOST=$SERVER_HOST -DBROKER_ENDPOINT=$BROKER_ENDPOINT \
               -DROOT_CA_CERT_PATH=$ROOT_CERT_PATH -DTHING_NAME=$THING_NAME \
               -DDEVICE_SERIAL_NUMBER=$DEV_SN
comment
}


build_fleet_prov_cmd(){

    # Just for test
    CLAIM_CERT_PATH=$PRIV_KEY_PATH
    CLAIM_PRIVATE_KEY_PATH=$PRIV_KEY_PATH
    PROV_TEMPLATE_NAME=$CERT_DIR/device/c-test-thing/prov_exp_tmplate.json

    FLEET_PROV_CMD=" $NORMAL_CMD \
               -DCLAIM_CERT_PATH=$CLAIM_CERT_PATH -DCLAIM_PRIVATE_KEY_PATH=$CLAIM_PRIVATE_KEY_PATH \
               -DPROVISIONING_TEMPLATE_NAME=$PROV_TEMPLATE_NAME"

    echo "
    cmake -S . -Bbuild \
               -DAWS_IOT_ENDPOINT=$EP -DCLIENT_CERT_PATH=$CLIENT_CERT_PATH \
               -DCLIENT_PRIVATE_KEY_PATH=$PRIV_KEY_PATH \
               -DSERVER_HOST=$SERVER_HOST -DBROKER_ENDPOINT=$BROKER_ENDPOINT \
               -DROOT_CA_CERT_PATH=$ROOT_CERT_PATH -DTHING_NAME=$THING_NAME \
               -DDEVICE_SERIAL_NUMBER=$DEV_SN \
               -DCLAIM_CERT_PATH=$CLAIM_CERT_PATH -DCLAIM_PRIVATE_KEY_PATH=$CLAIM_PRIVATE_KEY_PATH \
               -DPROVISIONING_TEMPLATE_NAME=$PROV_TEMPLATE_NAME
    "


    echo "===================================================="


    echo "build command : cmake -S . $FLEET_PROV_CMD $BUILD_APPEND"

    cmake -S . $FLEET_PROV_CMD $BUILD_APPEND

 <<comment
    cmake -S . -Bbuild \
               -DAWS_IOT_ENDPOINT=$EP -DCLIENT_CERT_PATH=$CLIENT_CERT_PATH \
               -DCLIENT_PRIVATE_KEY_PATH=$PRIV_KEY_PATH \
               -DSERVER_HOST=$SERVER_HOST -DBROKER_ENDPOINT=$BROKER_ENDPOINT \
               -DROOT_CA_CERT_PATH=$ROOT_CERT_PATH -DTHING_NAME=$THING_NAME \
               -DDEVICE_SERIAL_NUMBER=$DEV_SN \
               -DCLAIM_CERT_PATH=$CLAIM_CERT_PATH -DCLAIM_PRIVATE_KEY_PATH=$CLAIM_PRIVATE_KEY_PATH \
               -DPROVISIONING_TEMPLATE_NAME=$PROV_TEMPLATE_NAME
comment
}

#build_device_cmd
#build_normal_case_cmd

build_fleet_prov_cmd
