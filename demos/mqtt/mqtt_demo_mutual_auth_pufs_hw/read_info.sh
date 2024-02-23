#!/bin/bash
# Copyright 2022-2024 PUFsecurity
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

sar -r 1 1 -o tmp1 &>/dev/null;sadf tmp1 -dh --iface=eth0 -- -u -r -n DEV > data.csv
who -b | awk '{print $3,$4, $5}' > data.txt