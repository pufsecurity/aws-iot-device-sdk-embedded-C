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

BIN_DIR=$PWD
SDK_EXE_ROOT_DIR="$(dirname "$BIN_DIR")"
#echo "SDK_EXE_ROOT_DIR : $SDK_EXE_ROOT_DIR"
LIB_DIR=$SDK_EXE_ROOT_DIR/lib

export LD_LIBRARY_PATH=$LIB_DIR
echo "LD_LIBRARY_PATH=$LIB_DIR"
