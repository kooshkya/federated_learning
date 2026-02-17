from scapy.all import Packet, Ether, IP, bind_layers
from scapy.fields import BitField

# Constants to match P4
TYPE_IPV4 = 0x800
TYPE_AGGREGATION = 0x1234

class Aggregation(Packet):
    name = "Aggregation"
    fields_desc = []
    # TODO: Add fields for the aggregation packet


bind_layers(Ether, Aggregation, type=TYPE_AGGREGATION)
bind_layers(Ether, IP, type=TYPE_IPV4)
bind_layers(Aggregation, IP)
