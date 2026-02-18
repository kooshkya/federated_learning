/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_AGGREGATION = 0x1234;

const bit<8> NUM_WORKERS = 3;
const bit<32> MAX_WEIGHTS = 512;

/* ================= HEADERS ================= */

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

header aggregation_t {
    bit<16> round;
    bit<8>  worker_id;
    bit<16> weight_index;
    bit<16> total_weights;
    bit<32> value;
}

/* ================= METADATA ================= */

struct metadata {
    bit<32> current_sum;
    bit<8>  bitmap;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    aggregation_t aggregation;
}

/* ================= REGISTERS ================= */

register<bit<32>>(MAX_WEIGHTS) weight_sums;
register<bit<8>>(MAX_WEIGHTS)  weight_bitmap;

/* ================= PARSER ================= */

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_AGGREGATION: parse_aggregation;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_aggregation {
        packet.extract(hdr.aggregation);
        transition accept;
    }
}

/* ================= VERIFY ================= */

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

/* ================= INGRESS ================= */

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop; }
        size = 1024;
        default_action = drop();
    }

    /* ---------- Multicast aggregation ---------- */
    action multicast_to_all() {
        standard_metadata.mcast_grp = 1;
    }

    action process_weight() {

        bit<32> idx = (bit<32>) hdr.aggregation.weight_index;

        weight_sums.read(meta.current_sum, idx);
        weight_bitmap.read(meta.bitmap, idx);

        meta.current_sum = meta.current_sum + hdr.aggregation.value;

        bit<8> worker_mask = (bit<8>)1 << (hdr.aggregation.worker_id - 1);
        meta.bitmap = meta.bitmap | worker_mask;

        weight_sums.write(idx, meta.current_sum);
        weight_bitmap.write(idx, meta.bitmap);

        if (meta.bitmap == 0b111) {

            bit<32> divisor = (bit<32>) NUM_WORKERS;
            bit<32> avg = meta.current_sum / divisor;

            hdr.aggregation.value = avg;

            weight_sums.write(idx, 0);
            weight_bitmap.write(idx, 0);

            multicast_to_all();
        } else {
            drop();
        }
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        else if (hdr.aggregation.isValid()) {
            process_weight();
        }
    }
}

/* ================= EGRESS ================= */

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {}
}

/* ================= CHECKSUM ================= */

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

/* ================= DEPARSER ================= */

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        if (hdr.ipv4.isValid()) packet.emit(hdr.ipv4);
        if (hdr.aggregation.isValid()) packet.emit(hdr.aggregation);
    }
}

/* ================= SWITCH ================= */

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
