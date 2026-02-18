import argparse
import sys
import threading
import time
from typing import Dict, List

import numpy as np
from scapy.all import sniff, sendp, Ether, get_if_hwaddr
from scapy.packet import Packet

from config.config import AppConfig, load_config
from ml.data_loader import load_multi_mnist
from ml.model import SimpleNeuralNetwork
from protocol.layers import Aggregation
from utils.network import get_if
from utils.tracker import ResultsTracker

class Worker:
    def __init__(self, worker_id: int, config: AppConfig):
        self.worker_id = worker_id
        self.config = config

        self.bitmap_position = 2 ** (worker_id - 1)
        self.iface = get_if()

        self.results_tracker = ResultsTracker(worker_id)
        self.model = SimpleNeuralNetwork(
            input_size=self.config.model_params.input_size,
            hidden_size=self.config.model_params.hidden_size,
            output_size=self.config.model_params.output_size
        )

        self.received_weights: Dict[int, np.ndarray] = {}
        self.received_event = threading.Event()
        self.current_round = 0

        self.receiver_thread = threading.Thread(target=self._packet_receiver, daemon=True)
        self.receiver_thread.start()

    def _packet_receiver(self):
        print(f"Starting packet receiver on {self.iface}...")
        try:
            sniff(
                filter="ether proto 0x1234",
                iface=self.iface,
                prn=self._handle_packet
            )
        except Exception as e:
            print(f"Error in packet receiver: {e}", file=sys.stderr)

    def _handle_packet(self, pkt: Packet):
        if pkt.haslayer(Aggregation):
            agg = pkt[Aggregation]
            
            # Ignore own packets
            if agg.worker_id == self.worker_id:
                return
            
            # Ignore packets from different rounds (basic sync mechanism)
            if agg.round_id != self.current_round + 1:
                return

            # Decode weights: Int -> Float
            scaling_factor = 10000.0
            weights_received = np.array(agg.weights, dtype=np.float32) / scaling_factor
            
            print(f"  [+] Received weights from Worker {agg.worker_id}")
            self.received_weights[agg.worker_id] = weights_received
            
            # If we received from all other workers, trigger event
            if len(self.received_weights) == (self.config.protocol.num_workers - 1):
                self.received_event.set()

    def send_model_weights(self):
        print("  [>] Broadcasting weights...")
        weights = self.model.get_weights() # Gets scaled integers
        
        # Broadcast to FF:FF:FF:FF:FF:FF
        pkt = Ether(src=get_if_hwaddr(self.iface), dst="ff:ff:ff:ff:ff:ff") / \
              Aggregation(round_id=self.current_round + 1, 
                          worker_id=self.worker_id, 
                          weights=weights)
        
        sendp(pkt, iface=self.iface, verbose=False)

    def run_training_round(self):
        print(f"Loading data for round {self.current_round + 1}...")
        (X_train, y_train), (X_test, y_test) = load_multi_mnist(
            digits=[1, 2, 3],
            num_features=self.config.model_params.input_size,
            num_samples=self.config.training.samples_per_worker,
            num_workers=self.config.protocol.num_workers
        )

        print(f"Training on {len(X_train)} samples...")
        self.model.train(
            X_train, y_train,
            epochs=self.config.training.epochs_per_round,
            learning_rate=self.config.training.learning_rate,
            momentum=self.config.training.momentum
        )

        y_pred_probs = self.model.forward(X_train)
        y_one_hot = np.eye(self.config.model_params.output_size)[y_train]
        loss = self.model.compute_loss(y_one_hot, y_pred_probs)
        train_acc = self.model.evaluate(X_train, y_train)
        self.results_tracker.add_round_results(self.current_round, loss, train_acc)
        print(f"Round {self.current_round + 1} - Pre-aggregation training accuracy: {train_acc:.4f}")
        
        # 1. Send Weights
        self.send_model_weights()
        
        # 2. Wait for peers
        print("Waiting for aggregated model from peers...")
        self.received_event.wait(timeout=60)
        
        # 3. Aggregate
        # Get own weights manually (as floats) to mix with received floats
        own_weights = np.concatenate([
            self.model.W1.flatten(), self.model.b1.flatten(),
            self.model.W2.flatten(), self.model.b2.flatten()
        ])
        
        all_weights = [own_weights]
        for w in self.received_weights.values():
            all_weights.append(w)
            
        print(f"  Aggregating {len(all_weights)} models...")
        avg_weights = np.mean(all_weights, axis=0)
        
        # 4. Update
        self.model.set_weights(avg_weights.tolist())

        post_acc = self.model.evaluate(X_test, y_test)
        print(f"Round {self.current_round + 1} - Post-aggregation test accuracy: {post_acc:.4f}\n")

    def start(self):
        num_rounds = self.config.training.rounds
        for r in range(num_rounds):
            self.current_round = r
            print(f"\n{'=' * 15} Round {r + 1}/{num_rounds} {'=' * 15}")

            self.received_weights.clear()
            self.received_event.clear()

            self.run_training_round()
            time.sleep(2)

        self.results_tracker.save_to_file()
        print("\nAll training rounds complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Federated Learning Worker Node')
    parser.add_argument('worker_id', type=int, help='Worker ID (1-indexed)')
    parser.add_argument('--config', type=str, default='config/config.json', help='Path to the configuration file')
    args = parser.parse_args()
