/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4       = 0x800;
const bit<16> TYPE_AGGREGATION = 0x1234;

/*-----------  Headers  -----------*/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header aggregation_t {
    bit<8>  round_num;
    bit<8>  worker_id;
    bit<8>  bitmap;
    bit<16> weight_index;
    bit<16> total_weights;
    bit<32> weight_value;   /* scaled: float * 10000, signed via two's complement */
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

struct metadata {
    bit<9>  ingress_port;
}

struct headers {
    ethernet_t    ethernet;
    aggregation_t aggregation;
    ipv4_t        ipv4;
}

/*-----------  Parser  -----------*/

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
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/*-----------  Verify Checksum  -----------*/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

/*-----------  Registers  -----------*/

// 3 workers, max 400 weights each — index = worker_id*400 + weight_index
// weight_value accumulator (signed 64-bit stored as bit<64>)
register<bit<32>>(1200) weight_accum;   // sum of scaled weights (fits: 3 * 10000 * 0.5 * scale ok with 32-bit? max sum = 3*5000=15000, fine)
register<bit<8>>(1)     round_bitmap;   // which workers sent weights this round
register<bit<8>>(1)     current_round;  // round the switch is currently aggregating

/*-----------  Ingress  -----------*/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // ---- IPv4 forwarding table ----
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

    // ---- Aggregation handling ----
    action store_weight() {
        // accumulate weight into register slot worker_id*400 + weight_index
        bit<32> idx = (bit<32>)hdr.aggregation.worker_id * 400 + (bit<32>)hdr.aggregation.weight_index;
        bit<32> cur;
        weight_accum.read(cur, idx);
        weight_accum.write(idx, cur + hdr.aggregation.weight_value);
    }

    action update_bitmap() {
        bit<8> bm;
        round_bitmap.read(bm, 0);
        bm = bm | hdr.aggregation.bitmap;
        round_bitmap.write(0, bm);
    }

    action broadcast() {
        standard_metadata.mcast_grp = 1;
    }

    apply {
        if (hdr.aggregation.isValid()) {
            // Check round consistency — reset accumulator if new round
            bit<8> sw_round;
            current_round.read(sw_round, 0);
            if (sw_round != hdr.aggregation.round_num) {
                // New round: reset bitmap (accumulators reset by workers sending first packet)
                round_bitmap.write(0, 0);
                current_round.write(0, hdr.aggregation.round_num);
            }

            store_weight();
            update_bitmap();

            // Check if all 3 workers have sent this weight_index
            bit<8> bm;
            round_bitmap.read(bm, 0);

            if (bm == 0x07) {
                // All workers sent — compute average for this weight_index and broadcast
                bit<32> s0;
                bit<32> s1;
                bit<32> s2;
                bit<32> widx = (bit<32>)hdr.aggregation.weight_index;
                weight_accum.read(s0, 0 * 400 + widx);
                weight_accum.read(s1, 1 * 400 + widx);
                weight_accum.read(s2, 2 * 400 + widx);
                bit<32> avg = (s0 + s1 + s2) / 3;
                hdr.aggregation.weight_value = avg;
                hdr.aggregation.worker_id = 0;  // from switch
                broadcast();
            } else {
                drop();
            }
        } else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*-----------  Egress  -----------*/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {}
}

/*-----------  Compute Checksum  -----------*/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
              hdr.ipv4.totalLen, hdr.ipv4.identification,
              hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl,
              hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

/*-----------  Deparser  -----------*/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.aggregation);
        packet.emit(hdr.ipv4);
    }
}

/*-----------  Switch  -----------*/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
