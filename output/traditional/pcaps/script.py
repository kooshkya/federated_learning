import os
import matplotlib.pyplot as plt
from collections import Counter
from scapy.all import rdpcap, Ether, bind_layers
from scapy.fields import ByteField, ShortField, SignedIntField
from scapy.packet import Packet

TYPE_AGGREGATION = 0x1234
PCAP_PATH = './' 

class Aggregation(Packet):
    name = "Aggregation"
    fields_desc = [
        ByteField("round_num",    0),
        ByteField("worker_id",    0),
        ShortField("weight_index",  0),
        ShortField("total_weights", 0),
        SignedIntField("weight_value", 0),
    ]

bind_layers(Ether, Aggregation, type=TYPE_AGGREGATION)

def get_cumulative_data():
    all_rounds = []
        
    pcap_files = [f for f in os.listdir(PCAP_PATH) if f.endswith('.pcap')]
    
    if not pcap_files:
        print("No pcap files found in the directory!")
        return [], []

    print(f"Processing {len(pcap_files)} files...")

    for filename in pcap_files:
        full_path = os.path.join(PCAP_PATH, filename)
        packets = rdpcap(full_path)
        
        for pkt in packets:
            if pkt.haslayer(Aggregation):
                all_rounds.append(pkt[Aggregation].round_num)

    counts_per_round = Counter(all_rounds)
    
    sorted_rounds = sorted(counts_per_round.keys())
    
    cumulative_counts = []
    current_sum = 0
    for r in sorted_rounds:
        current_sum += counts_per_round[r]
        cumulative_counts.append(current_sum)
        
    return sorted_rounds, cumulative_counts

def plot_cumulative(rounds, cumulative_values):
    plt.figure(figsize=(12, 6))
    
    plt.plot(rounds, cumulative_values, marker='o', linestyle='-', color='b', linewidth=2, markersize=6)
    
    plt.fill_between(rounds, cumulative_values, color='skyblue', alpha=0.4)
    
    plt.title('Cumulative Packet Count across Training Rounds', fontsize=14)
    plt.xlabel('Round Number', fontsize=12)
    plt.ylabel('Total Packets Sent (Cumulative)', fontsize=12)
    
    plt.xticks(rounds)
    plt.grid(True, linestyle='--', alpha=0.7)
    
    for i, val in enumerate(cumulative_values):
        plt.text(rounds[i], val, f'{val}', ha='right', va='bottom', fontsize=9)

    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    rounds, cumulative_data = get_cumulative_data()
    
    if rounds:
        plot_cumulative(rounds, cumulative_data)
    else:
        print("No Aggregation packets found.")
