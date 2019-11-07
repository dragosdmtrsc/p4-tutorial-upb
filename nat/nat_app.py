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
import sys
import argparse
import runtime_CLI
from sswitch_CLI import SimpleSwitchAPI

CLI_PATH = None

EXTERN_IP = "192.168.0.1"

current_nat_port = 1025
nat_mappings = {}

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

# This is a very basic implementation of a full-cone NAT for TCP traffic
# We do not maintain a state machine for each connection, so we are not able to
# cleanup the port mappings, but this is sufficient for demonstration purposes
def process_cpu_pkt(p):
    global current_nat_port
    global EXTERN_IP

    p_str = str(p)
    # 0-7  : preamble
    # 8   : iface
    # 9-  : data packet (TCP)
    if p_str[:8] != '\x00' * 8:
        return
    ip_hdr = None
    tcp_hdr = None
    try:
        p2 = Ether(p_str[11:])
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
        standard_client.bm_mt_add_entry
        # TODO: external to internal rule for this mapping
    sendp(p_str, iface=args.cpuport, verbose=0)

def main():
    sniff(iface=args.cpuport, prn=lambda x: process_cpu_pkt(x))

if __name__ == '__main__':
    main()
