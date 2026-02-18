from scapy.all import Packet, Ether, IP, bind_layers
from scapy.fields import BitField

# Constants to match P4
TYPE_IPV4 = 0x800
TYPE_AGGREGATION = 0x1234
SCALE = 10000

class Aggregation(Packet):
    name = "Aggregation"
    fields_desc = [
        BitField("round", 0, 16),
        BitField("worker_id", 0, 8),
        BitField("weight_index", 0, 16),
        BitField("total_weights", 0, 16),
        BitField("value", 0, 32)
    ]



bind_layers(Ether, Aggregation, type=TYPE_AGGREGATION)
bind_layers(Ether, IP, type=TYPE_IPV4)
bind_layers(Aggregation, IP)
