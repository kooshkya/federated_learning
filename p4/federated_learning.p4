/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*===========================================================================
  Constants
===========================================================================*/
const bit<16> TYPE_IPV4        = 0x0800;
const bit<16> TYPE_ARP         = 0x0806;
const bit<16> TYPE_AGGREGATION = 0x1234;

const bit<32> MAX_WEIGHTS      = 128;

/*===========================================================================
  Headers
===========================================================================*/

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

// ARP header (we only need to parse it, not modify it)
header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8>  hwAddrLen;
    bit<8>  protoAddrLen;
    bit<16> opcode;
    bit<48> senderHwAddr;
    bit<32> senderProtoAddr;
    bit<48> targetHwAddr;
    bit<32> targetProtoAddr;
}

// Custom aggregation header (etherType = 0x1234)
// worker_id  : which worker sent this packet (1, 2, or 3)
// weight_idx : which weight index this packet carries
// weight_val : quantised integer weight  (float * SCALE, truncated)
// round_id   : training round number
// is_agg     : 0 = worker->switch, 1 = switch->workers (aggregated result)
header aggregation_t {
    bit<8>  worker_id;
    bit<32> weight_idx;
    bit<32> weight_val;
    bit<16> round_id;
    bit<8>  is_agg;
}

/*===========================================================================
  Metadata
===========================================================================*/
struct metadata {
    bit<32> tmp_weight;
    bit<8>  worker_bitmask;
    bit<1>  all_received;
}

struct headers {
    ethernet_t    ethernet;
    ipv4_t        ipv4;
    arp_t         arp;
    aggregation_t aggregation;
}

/*===========================================================================
  Registers
===========================================================================*/

// Running integer sum of weights per index
register<bit<32>>(MAX_WEIGHTS) weight_accumulator;

// Bitmask: which workers have sent weight[i]
// bit0=worker1, bit1=worker2, bit2=worker3
register<bit<8>>(MAX_WEIGHTS) worker_bitmask_reg;

// Current active training round (for reset detection)
register<bit<16>>(1) current_round;

/*===========================================================================
  Parser
===========================================================================*/
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
            TYPE_IPV4:        parse_ipv4;
            TYPE_ARP:         parse_arp;
            TYPE_AGGREGATION: parse_aggregation;
            default:          accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_aggregation {
        packet.extract(hdr.aggregation);
        transition accept;
    }
}

/*===========================================================================
  Verify Checksum
===========================================================================*/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

/*===========================================================================
  Ingress
===========================================================================*/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /*--- Actions -----------------------------------------------------------*/
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(bit<48> dstMac, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstMac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // Flood to all ports except the ingress port (for ARP broadcasts)
    action broadcast() {
        standard_metadata.mcast_grp = 1;
    }

    action multicast_to_all() {
        standard_metadata.mcast_grp = 1;
    }

    /*--- IPv4 forwarding table --------------------------------------------*/
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {

        /*------ ARP: flood to all ports so hosts can resolve MACs --------*/
        if (hdr.arp.isValid()) {
            broadcast();
            return;
        }

        /*------ Regular IPv4 unicast packet ------*/
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            return;
        }

        /*------ Aggregation packet from a worker (is_agg == 0) -----------*/
        if (hdr.aggregation.isValid() && hdr.aggregation.is_agg == 0) {

            bit<32> idx  = hdr.aggregation.weight_idx;
            bit<8>  wid  = hdr.aggregation.worker_id;
            bit<32> wval = hdr.aggregation.weight_val;
            bit<16> rnd  = hdr.aggregation.round_id;

            // ---- Detect new round: reset per-index state ----------------
            bit<16> saved_round;
            current_round.read(saved_round, 0);

            if (rnd != saved_round) {
                weight_accumulator.write(idx, 0);
                worker_bitmask_reg.write(idx, 0);
                current_round.write(0, rnd);
            }

            // ---- Accumulate weight -------------------------------------
            bit<32> acc;
            weight_accumulator.read(acc, idx);
            acc = acc + wval;
            weight_accumulator.write(idx, acc);

            // ---- Mark this worker in the bitmask -----------------------
            // P4 does not allow variable-width shifts; use if-else
            bit<8> worker_bit = 0;
            if      (wid == 1) { worker_bit = 8w0x01; }
            else if (wid == 2) { worker_bit = 8w0x02; }
            else if (wid == 3) { worker_bit = 8w0x04; }

            bit<8> mask;
            worker_bitmask_reg.read(mask, idx);
            mask = mask | worker_bit;
            worker_bitmask_reg.write(idx, mask);

            // ---- Check whether all workers contributed -----------------
            // For 3 workers the complete mask is 0b00000111 = 0x07
            if (mask == 8w0x07) {
                // All workers sent this weight -> broadcast aggregate
                hdr.aggregation.is_agg    = 1;
                hdr.aggregation.weight_val = acc;

                // Reset for next round
                weight_accumulator.write(idx, 0);
                worker_bitmask_reg.write(idx, 0);

                multicast_to_all();
            } else {
                // Still waiting for other workers — drop this copy
                drop();
            }
        }

        /*------ Aggregated result coming back from multicast (is_agg==1) -*/
        // The multicast replication engine handles fan-out; nothing to do here.
    }
}

/*===========================================================================
  Egress
===========================================================================*/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        // Prune multicast: don't send the packet back out the port it came in on
        if (standard_metadata.egress_port == standard_metadata.ingress_port) {
            mark_to_drop(standard_metadata);
        }
    }
}

/*===========================================================================
  Compute Checksum
===========================================================================*/
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

/*===========================================================================
  Deparser
===========================================================================*/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.arp);
        packet.emit(hdr.aggregation);
    }
}

/*===========================================================================
  Switch instantiation
===========================================================================*/
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
