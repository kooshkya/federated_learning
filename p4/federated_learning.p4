/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4    = 0x0800;
const bit<16> TYPE_AGGREGATION = 0x1234;

/*************************************************************************
 * H E A D E R S
 *************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

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

// One weight per packet: index, total, round, worker, value
header aggregation_t {
    bit<8>  round_num;
    bit<8>  worker_id;
    bit<16> weight_index;
    bit<16> total_weights;
    bit<32> weight_value;   // float * 1_000_000, cast to int32
}

struct metadata {}

struct headers {
    ethernet_t    ethernet;
    aggregation_t aggregation;
    ipv4_t        ipv4;
}

/*************************************************************************
 * P A R S E R
 *************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_AGGREGATION: parse_aggregation;
            TYPE_IPV4:        parse_ipv4;
            default:          accept;
        }
    }

    state parse_aggregation {
        packet.extract(hdr.aggregation);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/*************************************************************************
 * C H E C K S U M   V E R I F I C A T I O N
 *************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

/*************************************************************************
 * I N G R E S S
 *************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    // Standard L2 unicast forward
    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    // Broadcast: send to all ports except ingress
    action broadcast() {
        standard_metadata.mcast_grp = 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            forward;
            drop;
            NoAction;
        }
        default_action = NoAction();
    }

    table ethernet_exact {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
            broadcast;
            drop;
            NoAction;
        }
        default_action = broadcast();
    }

    apply {
        if (hdr.aggregation.isValid()) {
            // Always broadcast aggregation packets to all hosts
            broadcast();
        } else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        } else {
            ethernet_exact.apply();
        }
    }
}

/*************************************************************************
 * E G R E S S
 *************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {
        // Drop packet if it would go back out the ingress port
        if (standard_metadata.egress_port == standard_metadata.ingress_port) {
            mark_to_drop(standard_metadata);
        }
    }
}

/*************************************************************************
 * C H E C K S U M   C O M P U T A T I O N
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
 * D E P A R S E R
 *************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.aggregation);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
 * S W I T C H
 *************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
