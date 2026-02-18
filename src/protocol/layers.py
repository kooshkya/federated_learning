from scapy.all import Packet, Ether, IP, bind_layers
from scapy.fields import ByteField, ShortField, SignedIntField

# Constants to match P4
TYPE_IPV4        = 0x0800
TYPE_AGGREGATION = 0x1234

SCALE_FACTOR = 1_000_000  # float * SCALE_FACTOR -> int32

class Aggregation(Packet):
    name = "Aggregation"
    fields_desc = [
        ByteField("round_num",    0),
        ByteField("worker_id",    0),
        ShortField("weight_index",  0),
        ShortField("total_weights", 0),
        SignedIntField("weight_value", 0),  # float * SCALE_FACTOR
    ]

bind_layers(Ether, Aggregation, type=TYPE_AGGREGATION)
bind_layers(Ether, IP,          type=TYPE_IPV4)
