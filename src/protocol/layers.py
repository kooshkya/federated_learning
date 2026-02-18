from scapy.all import Packet, Ether, IP, bind_layers
from scapy.fields import ByteField, ShortField, SignedIntField

TYPE_IPV4        = 0x800
TYPE_AGGREGATION = 0x1234

class Aggregation(Packet):
    name = "Aggregation"
    fields_desc = [
        ByteField("round_num",     0),
        ByteField("worker_id",     0),
        ByteField("bitmap",        0),
        ShortField("weight_index", 0),
        ShortField("total_weights",0),
        SignedIntField("weight_value",   0),
    ]

bind_layers(Ether, Aggregation, type=TYPE_AGGREGATION)
bind_layers(Ether, IP,          type=TYPE_IPV4)
bind_layers(Aggregation, IP)
