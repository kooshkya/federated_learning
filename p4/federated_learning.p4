/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_AGGREGATION = 0x1234;

// TODO: Define headers needed for regular IPv4 routing and aggregation

struct metadata {
    // TODO
}

struct headers {
    // TODO
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    // TODO
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // TODO
    apply {}
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    // TODO
    apply {}

}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    // TODO
     apply {}
}

control MyDeparser(packet_out packet, in headers hdr) {
    // TODO
    apply {}
}

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;