from scapy.all import Packet, Ether, IP, bind_layers
from scapy.fields import ShortField, IntField, SignedIntField

TYPE_IPV4 = 0x800
TYPE_AGGREGATION = 0x1234

class Aggregation(Packet):
    name = "Aggregation"
    fields_desc = [
        ShortField("round_num", 0),
        ShortField("worker_id", 0),
        IntField("weight_index", 0),
        IntField("total_weights", 0),
        SignedIntField("weight_value", 0),   # signed 32-bit; weights*1e6 fit fine in [-500000, 500000]
    ]

bind_layers(Ether, Aggregation, type=TYPE_AGGREGATION)
bind_layers(Ether, IP, type=TYPE_IPV4)
bind_layers(Aggregation, IP)
