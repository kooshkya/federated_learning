/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4       = 0x800;
const bit<16> TYPE_AGGREGATION = 0x1234;

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------
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
    bit<8>  round_num;
    bit<8>  worker_id;
    bit<8>  bitmap;
    bit<16> weight_index;
    bit<16> total_weights;
    bit<32> weight_value;
}

struct metadata {}

struct headers {
    ethernet_t    ethernet;
    aggregation_t aggregation;
    ipv4_t        ipv4;
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Verify Checksum
// ---------------------------------------------------------------------------
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

// ---------------------------------------------------------------------------
// Ingress
// ---------------------------------------------------------------------------
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // Registers
    register<int<32>>(1200) weight_accum;
    register<bit<8>>(400)   weight_bitmap;   // one bitmap per weight index
    register<bit<8>>(1)     current_round;


    action drop() {
        mark_to_drop(standard_metadata);
    }

    action broadcast() {
        standard_metadata.mcast_grp = 1;
    }

    // IPv4 forwarding table
    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop; NoAction; }
        default_action = drop();
    }

    apply {
        if (hdr.aggregation.isValid()) {

            // --- Round check / reset all bitmaps ---
            bit<8> sw_round;
            current_round.read(sw_round, 0);
            if (sw_round != hdr.aggregation.round_num) {
                // Reset every per-index bitmap
                // P4 can't loop, so use a recirculation trick or just rely on
                // the accum reset below. We'll handle it by resetting bitmap
                // at the same slot when we reset accumulators.
                current_round.write(0, hdr.aggregation.round_num);
            }

            // --- Accumulate (signed) ---
            bit<32> widx = (bit<32>)hdr.aggregation.weight_index;
            bit<32> idx  = (bit<32>)hdr.aggregation.worker_id * 400 + widx;
            int<32> cur;
            weight_accum.read(cur, idx);
            int<32> incoming = (int<32>)hdr.aggregation.weight_value;
            weight_accum.write(idx, cur + incoming);

            // --- Update per-index bitmap ---
            bit<8> bm;
            weight_bitmap.read(bm, widx);
            bm = bm | hdr.aggregation.bitmap;
            weight_bitmap.write(widx, bm);

            // --- Check if all 3 workers contributed for THIS index ---
            if (bm == 8w0x07) {
                int<32> s0; int<32> s1; int<32> s2;
                weight_accum.read(s0, 0 * 400 + widx);
                weight_accum.read(s1, 1 * 400 + widx);
                weight_accum.read(s2, 2 * 400 + widx);

                // Reset accumulators and bitmap for this index
                weight_accum.write(0 * 400 + widx, (int<32>)0);
                weight_accum.write(1 * 400 + widx, (int<32>)0);
                weight_accum.write(2 * 400 + widx, (int<32>)0);
                weight_bitmap.write(widx, 8w0);

                int<32> total = s0 + s1 + s2;
                hdr.aggregation.weight_value = (bit<32>)total;
                hdr.aggregation.worker_id    = 8w3;
                hdr.aggregation.bitmap       = 8w0x07;
                broadcast();

            } else {
                drop();
            }

        } else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }

}

// ---------------------------------------------------------------------------
// Egress
// ---------------------------------------------------------------------------
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {}
}

// ---------------------------------------------------------------------------
// Compute Checksum
// ---------------------------------------------------------------------------
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

// ---------------------------------------------------------------------------
// Deparser
// ---------------------------------------------------------------------------
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.aggregation);
        packet.emit(hdr.ipv4);
    }
}

// ---------------------------------------------------------------------------
// Switch Architecture
// ---------------------------------------------------------------------------
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
