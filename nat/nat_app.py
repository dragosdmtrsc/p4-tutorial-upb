# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from scapy.all import *
import runtime_CLI
from sswitch_CLI import SimpleSwitchAPI
from bm_runtime.standard.ttypes import *

parser = runtime_CLI.get_parser()
parser.add_argument('--cpuport', help='cpu port',
                        type=str, action="store", default='veth250')
args = parser.parse_args()
#don't care about multicast in this example
args.pre = runtime_CLI.PreType.None

services = runtime_CLI.RuntimeAPI.get_thrift_services(args.pre)
services.extend(SimpleSwitchAPI.get_thrift_services())

# standard client deals in tables (add, delete, get)
# mc_client deals with multicast groups
# sswitch_client deals with mirroring
# for this very simple example, focus is on standard_client
standard_client, mc_client, sswitch_client = runtime_CLI.thrift_connect(
    args.thrift_ip, args.thrift_port, services
)
# load table info from compiled json
runtime_CLI.load_json_config(standard_client, args.json)


def get_table(table_name):
    key = (runtime_CLI.ResType.table, table_name)
    if key in runtime_CLI.SUFFIX_LOOKUP_MAP:
        return runtime_CLI.SUFFIX_LOOKUP_MAP[(runtime_CLI.ResType.table, table_name)]
    raise Exception("no table " + table_name + " found")

def i2bytes(nr, bw):
    return runtime_CLI.int_to_bytes(nr, (bw + 7) / 8)

# relating a P4 table to a runtime table. Let:
# table T {
#   keys { k1 : exact; k2 : ternary; k3 : lpm; };
#   actions { a1(); a2(); }
# }
# action a1(bit<32> p1, bit<16> p2) {}
# Example: Adding a table entry T for action a1:
# Step 1: build keys
# Step 2: build action parameters
# Step 3: client.bm_mt_add_entry(0, T, match, action_name, action_data, BmAddEntryOptions(priority=prio))

# adds an entry in table T with action name act1
# k1, k2*, k3*, p1, p2 are integers
# prio is an integer standing for priority of the entry. The higher the priority,
# the higher in the table the entry will be.
# If a packet matches two entries, the one with HIGHEST priority wins
def addTEntryForAct1(k1, k2value, k2mask, k3value, k3prefix, p1, p2, prio):
    keyparams = []
    table = get_table('T')
    bitwidths = [bw for (_, _, bw) in table.key]
    # 1: encode k1
    k1bw = bitwidths[0]
    key = runtime_CLI.bytes_to_string(i2bytes(k1, k1bw))
    param = BmMatchParam(type=BmMatchParamType.EXACT,
                         exact=BmMatchParamExact(key))
    keyparams.append(param)

    # 2: encode k2
    k2bw = bitwidths[1]
    keyv = runtime_CLI.bytes_to_string(i2bytes(k2value, k2bw))
    keym = runtime_CLI.bytes_to_string(i2bytes(k2mask, k2bw))
    param = BmMatchParam(type=BmMatchParamType.TERNARY,
                         ternary=BmMatchParamTernary(keyv, keym))
    keyparams.append(param)

    # 3: encode k3
    k3bw = bitwidths[1]
    keyv = runtime_CLI.bytes_to_string(i2bytes(k3value, k3bw))
    param = BmMatchParam(type=BmMatchParamType.LPM,
                         lpm=BmMatchParamLPM(keyv, k3prefix))
    keyparams.append(param)

    # encode action param p1
    action_data = []
    bwp1 = 32
    action_data += [runtime_CLI.bytes_to_string(i2bytes(p1, bwp1))]
    # encode action param p2
    bwp2 = 16
    action_data += [runtime_CLI.bytes_to_string(i2bytes(p2, bwp2))]
    global standard_client
    standard_client.bm_mt_add_entry(
        0, table.name, keyparams, "a1", action_data,
        BmAddEntryOptions(priority=prio)
    )


EXTERN_IP = "192.168.0.1"

current_nat_port = 1025
nat_mappings = {}
def process_cpu_pkt(p):
    global current_nat_port
    global EXTERN_IP

    p_str = str(p)
    # 0-7  : preamble (all zeros)
    # 8   : iface
    # 9-  : data packet (TCP)
    if p_str[:8] != '\x00' * 8:
        return
    ip_hdr = None
    tcp_hdr = None
    try:
        p2 = Ether(p_str[9:])
        ip_hdr = p2['IP']
        tcp_hdr = p2['TCP']
    except:
        # non IP/TCP packets are dropped
        return
    print "Packet received"
    print p2.summary()
    if (ip_hdr.src, tcp_hdr.sport) not in nat_mappings:
        ext_port = current_nat_port
        current_nat_port += 1
        print "Allocating external port", ext_port
        nat_mappings[(ip_hdr.src, tcp_hdr.sport)] = ext_port
        # TODO: internal to external rule for this mapping
        # TODO: external to internal rule for this mapping
    sendp(p_str, iface=args.cpuport, verbose=0)

def main():
    sniff(iface=args.cpuport, prn=lambda x: process_cpu_pkt(x))
    #addTEntryForAct1(1, 1, 1, 0, 0, 5, 5, 10)
    #addTEntryForAct1(1, 2, 3, 0xf0000000, 15, 6, 6, 20)

if __name__ == '__main__':
    main()
