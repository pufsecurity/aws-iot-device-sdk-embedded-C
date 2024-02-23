#!/bin/sh
# Copyright 2023-2024 PUFsecurity
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

PUFSE_CHIP=TRUE
#PUFSE_CHIP=FALSE

if [ "$PUFSE_CHIP" = "TRUE" ]; then

    CERT_PATH=$PWD/certs-puf/device/c-test-thing-uid-pufse
    CLIENT_ID=puf_e001b04e82dec354b18ec7b904866c0291848c42173391d38eb35e731ca5c5d2
    CLIENT_CERT=pufs_e001b04e-pubkey.pem.crt

else
    # pufse fpga or pufcc

    CERT_PATH=$PWD/certs-puf/device/c-test-thing-uid
    CLIENT_ID=puf_4768418ee32618c6ddce00bbcb67f896c3fc0087639219c7ca3240949be47a37
    # puf_000a35001e57_4768418ee32618c6ddce00bbcb67f896c3fc0087639219c7ca3240949be47a37
    CLIENT_CERT=pufs_4768418e-pubkey.pem.crt
fi

#cd bin


echo "cmd: ./mqtt_demo_mutual_auth_pufs_hw -c $CLIENT_ID  -f $CERT_PATH/$CLIENT_CERT"
./mqtt_demo_mutual_auth_pufs_hw -c $CLIENT_ID  -f $CERT_PATH/$CLIENT_CERT
