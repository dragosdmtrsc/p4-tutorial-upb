#include <core.p4>
#include <v1model.p4>

// this structure is specific to the BMV2 target
// The fields herein have a well documented semantics.
// WARNING: do not add custom metadata here, the compiler
// will reject them. Add them to meta_t instead
struct intrinsic_metadata_t {
    bit<4>  mcast_grp;
    bit<4>  egress_rid;
    bit<16> mcast_hash;
    bit<32> lf_field_list;
}

//TODO: add custom metadata fields here
//HINT: they must be of type bit<N> or (rarely) int<N>
struct meta_t {
	bit<32> dummy;
	bit<32> k1;
	bit<32> k2;
	bit<32> k3;
}

// ensures communication between nat and cpu
header cpu_header_t {
    bit<64> preamble;
    bit<8>  if_index;
}
// contains the standard ethernet header
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// contains a standard ipv4 header
header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

// tcp header
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

// a wrapper for all user-defined metadata
// Why not just use meta_t? p4c BMV2 compiler
// mandates that user-defined metadata is a structure
// where all fields are of structure types
struct metadata {
    @name(".meta") 
    meta_t meta;
}

// a wrapper for all user-defined headers
struct headers {
    @name(".cpu_header") 
    cpu_header_t cpu_header;
    @name(".ethernet") 
    ethernet_t   ethernet;
    @name(".ipv4") 
    ipv4_t       ipv4;
    @name(".tcp") 
    tcp_t        tcp;
}

// program entry point
parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_cpu_header") state parse_cpu_header {
        packet.extract(hdr.cpu_header);
        transition parse_ethernet;
    }
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
		// etherType = 0x800 => ipv4 header follows
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
		// ipproto = 6 => tcp header follows
        transition select(hdr.ipv4.protocol) {
            8w0x6: parse_tcp;
            default: accept;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    @name(".start") state start {
		// STEP 1: if the first 64 bits of the parser are zeros => (not valid ethernet dst addr + src addr)
		// then it is a CPU header
		// otherwise treat the packet as an ethernet frame
        transition select((packet.lookahead<bit<64>>())[63:0]) {
            64w0: parse_cpu_header;
            default: parse_ethernet;
        }
    }
}
// ingress pipeline starts
control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".a1") action a1(bit<32> p1, bit<16> p2) {
        #dummy action to demonstrate control plane usage
    }
    @name(".a2") action a2() {}
    @name(".T") table T {
        key = {
            meta.meta.k1 : exact;
            meta.meta.k2 : ternary;
            meta.meta.k3 : lpm;
        }
        actions = {
            a1(); a2();
        }
        size = 1024;
        default_action = a2;
    }


    @name(".set_dmac") action set_dmac(bit<48> dmac) {
    }
    @name("._drop") action _drop() {
        mark_to_drop(standard_metadata);
    }
    @name(".set_if_info") action set_if_info(bit<1> is_ext) {
    }
    @name(".set_nhop") action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
    }
    @name(".nat_miss_int_to_ext") action nat_miss_int_to_ext() {
		// TODO: code the case of nat table miss
		// HINT: the packet came in from an internal port and
		// it was not found in the nat table => need to send it to cpu, which will add
		// it to the nat table and then re-inject the packet in the pipeline
		// HINT: use clone primitive clone3(CloneType.I2E, clone session, { saved metadata });
    }
    @name(".nat_miss_ext_to_int") action nat_miss_ext_to_int() {
		// TODO: if packet came in from the outside and it was not in the nat table,
		// then drop it
    }
    @name(".nat_hit_int_to_ext") action nat_hit_int_to_ext(bit<32> srcAddr, bit<16> srcPort) {
		// TODO: packet from inside and found in table => do the actual NAT
    }
    @name(".nat_hit_ext_to_int") action nat_hit_ext_to_int(bit<32> dstAddr, bit<16> dstPort) {
		// TODO: packet from outside and previously nat'ed => reverse NAT
    }
    @name(".forward") table forward {
        actions = {
            set_dmac;
            _drop;
        }
        key = {
			// TODO: add key match here for ARP table ARP table maps IPv4 -> MAC
			// HINT: rewrite destination MAC address to 
			// the one specified by ARP: that is 
			// ethernet.dstAddr = ARP[ipv4.dst]
			meta.meta.dummy : exact;
        }
        size = 512;
    }
    @name(".if_info") table if_info {
        actions = {
            _drop;
            set_if_info;
        }
        key = {
			// match against the port that 
			// the packet came in from and
			// set a flag indicating whether the port
			// is internal or external. 
			// A source port may be invalid. If so,
			// then drop the packet.
			// HINT: need a metadata field which says
			// what port the packet came in. Watch out for
			// cpu => nat communication. What happens to a packet
			// re-injected in the pipeline
			meta.meta.dummy : exact;
        }
    }
    @name(".ipv4_lpm") table ipv4_lpm {
        actions = {
            set_nhop;
            _drop;
        }
        key = {
            // TODO: longest prefix match against 
			// the packet's IPv4 destination address
			// HINT: this is the routing table (or FIB)
			meta.meta.dummy : exact;
        }
        size = 1024;
    }
    @name(".nat") table nat {
        actions = {
            _drop;
            nat_miss_int_to_ext;
            nat_miss_ext_to_int;
            nat_hit_int_to_ext;
            nat_hit_ext_to_int;
        }
        key = {
			// TODO: nat match keys here:
			// HINT: this table just matches a connection 5-tuple
			// and looks if the packet came in from an external 
			// or an internal interface
			meta.meta.dummy : exact;
        }
        size = 128;
    }
    apply {
        T.apply();
        if_info.apply();
        nat.apply();
        if (true /* TODO: write condition to forward the packet: 
			neither if_info nor nat has dropped it + 
			ipv4 header is sane (?) */) {
            ipv4_lpm.apply();
            forward.apply();
        }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".do_rewrites") action do_rewrites(bit<48> smac) {
    }
    @name("._drop") action _drop() {
        mark_to_drop(standard_metadata);
    }
    @name(".do_cpu_encap") action do_cpu_encap() {
    }
    @name(".send_frame") table send_frame {
        actions = {
            do_rewrites;
            _drop;
        }
        key = {
			// sets src MAC address of egress_port
			// send_frame maps a port -> MAC address
			// TODO: write code for do_rewrites action
			// that is: ethernet.srcAddr = send_frame[egress_port]
            standard_metadata.egress_port: exact;
        }
        size = 256;
    }
    @name(".send_to_cpu") table send_to_cpu {
        actions = {
			// TODO: write code for cpu encap
			// recall that communication between nat <=> cpu
			// is ensured by the cpu_header header. 
			// HINT: it must be valid at the end of the pipeline
			// and must contain the port which the packet arrived on
            do_cpu_encap;
        }
    }
    apply {
        if (standard_metadata.instance_type == 32w0) {
            send_frame.apply();
        }
        else {
            send_to_cpu.apply();
        }
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
		//TODO: add deparser implementation here:
		//HINT: needs to be the inverse of the parser
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        //TODO: uncomment these lines at the end
        //verify_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        //verify_checksum_with_payload(hdr.tcp.isValid(), { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, hdr.ipv4.protocol, meta.meta.tcpLength, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.tcp.seqNo, hdr.tcp.ackNo, hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.window, hdr.tcp.urgentPtr }, hdr.tcp.checksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        //TODO: uncomment these lines at the end
        //update_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        //update_checksum_with_payload(hdr.tcp.isValid(), { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, hdr.ipv4.protocol, meta.meta.tcpLength, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.tcp.seqNo, hdr.tcp.ackNo, hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.window, hdr.tcp.urgentPtr }, hdr.tcp.checksum, HashAlgorithm.csum16);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

