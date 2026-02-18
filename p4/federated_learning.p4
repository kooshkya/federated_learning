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
    // weight_accum[worker_id * MAX_WEIGHTS + weight_index]
    // MAX_WEIGHTS = 400 (15*8 + 8*3 = 120+24 = 144 weights, round up to 400)
    register<bit<32>>(1200) weight_accum;  // 3 workers * 400 weights
    register<bit<8>>(1)     round_bitmap;
    register<bit<8>>(1)     current_round;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(bit<48> dstMac, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstMac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop; NoAction; }
        size = 1024;
        default_action = drop();
    }

    action broadcast() {
        standard_metadata.mcast_grp = 1;
    }

    apply {
        if (hdr.aggregation.isValid()) {
            // Check/reset round
            bit<8> sw_round;
            current_round.read(sw_round, 0);
            if (sw_round != hdr.aggregation.round_num) {
                round_bitmap.write(0, 0);
                current_round.write(0, hdr.aggregation.round_num);
            }

            // Accumulate this worker's weight
            bit<32> idx = (bit<32>)hdr.aggregation.worker_id * 400 +
                          (bit<32>)hdr.aggregation.weight_index;
            bit<32> cur;
            weight_accum.read(cur, idx);
            weight_accum.write(idx, cur + hdr.aggregation.weight_value);

            // Update bitmap
            bit<8> bm;
            round_bitmap.read(bm, 0);
            bm = bm | hdr.aggregation.bitmap;
            round_bitmap.write(0, bm);

            if (bm == 0x07) {
                // All 3 workers sent this weight index — compute average
                bit<32> widx = (bit<32>)hdr.aggregation.weight_index;
                bit<32> s0; bit<32> s1; bit<32> s2;
                weight_accum.read(s0, 0 * 400 + widx);
                weight_accum.read(s1, 1 * 400 + widx);
                weight_accum.read(s2, 2 * 400 + widx);

                bit<32> total = s0 + s1 + s2;

                // Divide by 3: x/3 ≈ (x * 43691) >> 17
                bit<64> total64 = (bit<64>)total;
                bit<64> avg64   = (total64 * 43691) >> 17;
                bit<32> avg     = (bit<32>)avg64;

                hdr.aggregation.weight_value = avg;
                hdr.aggregation.worker_id    = 0;
                hdr.aggregation.bitmap       = 0x07;
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
