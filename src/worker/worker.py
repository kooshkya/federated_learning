import argparse
import sys
import threading
import time
import struct
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

# Scale factor: weights are in [-0.5, 0.5], scale to integers in [-5000, 5000]
SCALE_FACTOR = 10000

class Worker:
    def __init__(self, worker_id: int, config: AppConfig):
        self.worker_id = worker_id
        self.config    = config

        # bitmap bit position: worker 1 → 0x01, worker 2 → 0x02, worker 3 → 0x04
        self.bitmap_position = 1 << (worker_id - 1)
        self.iface = get_if()

        self.results_tracker = ResultsTracker(worker_id)
        self.model = SimpleNeuralNetwork(
            input_size  = self.config.model_params.input_size,
            hidden_size = self.config.model_params.hidden_size,
            output_size = self.config.model_params.output_size
        )

        # Will store index→scaled_int once aggregated packet arrives
        self._agg_buffer: Dict[int, int] = {}
        self._total_weights = 0
        self.received_event  = threading.Event()
        self.current_round   = 0

        self.receiver_thread = threading.Thread(
            target=self._packet_receiver, daemon=True)
        self.receiver_thread.start()

    # ------------------------------------------------------------------
    # Receiver
    # ------------------------------------------------------------------
    def _packet_receiver(self):
        print(f"[W{self.worker_id}] Listening on {self.iface}...")
        try:
            sniff(
                filter="ether proto 0x1234",
                iface=self.iface,
                prn=self._handle_packet
            )
        except Exception as e:
            print(f"Error in receiver: {e}", file=sys.stderr)

    def _handle_packet(self, pkt: Packet):
        if not pkt.haslayer(Aggregation):
            return
        agg = pkt[Aggregation]

        # Only accept broadcast aggregation packets (worker_id == 0)
        if agg.worker_id != 0:
            return
        # Only accept packets for the current round
        if agg.round_num != self.current_round:
            return

        idx   = agg.weight_index
        value = agg.weight_value

        self._agg_buffer[idx] = value
        self._total_weights   = agg.total_weights

        # When we've collected all weight indices, rebuild the model
        if len(self._agg_buffer) == self._total_weights:
            self._apply_aggregated_weights()
            self.received_event.set()

    def _apply_aggregated_weights(self):
        """Convert scaled integers back to floats and set model weights."""
        flat = np.array(
            [self._agg_buffer[i] for i in range(self._total_weights)],
            dtype=np.float32
        ) / SCALE_FACTOR

        W1_size = self.config.model_params.input_size  * self.config.model_params.hidden_size
        b1_size = self.config.model_params.hidden_size
        W2_size = self.config.model_params.hidden_size * self.config.model_params.output_size
        b2_size = self.config.model_params.output_size

        offset = 0
        W1 = flat[offset:offset+W1_size].reshape(
            self.config.model_params.input_size, self.config.model_params.hidden_size)
        offset += W1_size
        b1 = flat[offset:offset+b1_size]; offset += b1_size
        W2 = flat[offset:offset+W2_size].reshape(
            self.config.model_params.hidden_size, self.config.model_params.output_size)
        offset += W2_size
        b2 = flat[offset:offset+b2_size]

        self.model.set_weights([W1, b1, W2, b2])
        print(f"[W{self.worker_id}] Applied aggregated weights ({self._total_weights} values).")

        # Reset buffer for next round
        self._agg_buffer.clear()
        self._total_weights = 0

    # ------------------------------------------------------------------
    # Sender
    # ------------------------------------------------------------------
    def send_model_weights(self):
        weights = self.model.get_weights()      # [W1, b1, W2, b2]
        flat    = np.concatenate([w.flatten() for w in weights])
        total   = len(flat)

        src_mac = get_if_hwaddr(self.iface)
        # Broadcast MAC for aggregation packets
        dst_mac = "ff:ff:ff:ff:ff:ff"

        print(f"[W{self.worker_id}] Sending {total} weights for round {self.current_round}...")
        for idx, val in enumerate(flat):
            scaled = int(round(float(val) * SCALE_FACTOR))
            # Clamp to 32-bit signed range (safe: max |val|=0.5 → ±5000)
            scaled = max(-2**31, min(2**31 - 1, scaled))

            pkt = (
                Ether(src=src_mac, dst=dst_mac, type=0x1234) /
                Aggregation(
                    round_num    = self.current_round,
                    worker_id    = self.worker_id - 1,   # 0-indexed for P4 register slot
                    bitmap       = self.bitmap_position,
                    weight_index = idx,
                    total_weights= total,
                    weight_value = scaled & 0xFFFFFFFF    # unsigned 32-bit
                )
            )
            sendp(pkt, iface=self.iface, verbose=False)

        print(f"[W{self.worker_id}] Done sending weights.")

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------
    def run_training_round(self):
        print(f"[W{self.worker_id}] Loading data...")
        (X_train, y_train), (X_test, y_test) = load_multi_mnist(
            digits=[1, 2, 3],
            num_features = self.config.model_params.input_size,
            num_samples  = self.config.training.samples_per_worker,
            num_workers  = self.config.protocol.num_workers
        )

        print(f"[W{self.worker_id}] Training ({len(X_train)} samples)...")
        self.model.train(
            X_train, y_train,
            epochs        = self.config.training.epochs_per_round,
            learning_rate = self.config.training.learning_rate,
            momentum      = self.config.training.momentum
        )

        y_pred_probs = self.model.forward(X_train)
        y_one_hot    = np.eye(self.config.model_params.output_size)[y_train]
        loss         = self.model.compute_loss(y_one_hot, y_pred_probs)
        train_acc    = self.model.evaluate(X_train, y_train)
        self.results_tracker.add_round_results(self.current_round, loss, train_acc)
        print(f"[W{self.worker_id}] Round {self.current_round+1} pre-agg train acc: {train_acc:.4f}")

        self._agg_buffer.clear()
        self.send_model_weights()

        print(f"[W{self.worker_id}] Waiting for aggregated model...")
        self.received_event.wait(timeout=60)
        if not self.received_event.is_set():
            print(f"[W{self.worker_id}] WARNING: Timeout waiting for aggregation!")

        post_acc = self.model.evaluate(X_test, y_test)
        print(f"[W{self.worker_id}] Round {self.current_round+1} post-agg test acc: {post_acc:.4f}\n")

    def start(self):
        num_rounds = self.config.training.rounds
        for r in range(num_rounds):
            self.current_round = r
            print(f"\n{'='*15} Round {r+1}/{num_rounds} {'='*15}")
            self.received_event.clear()
            self.run_training_round()
            time.sleep(2)

        self.results_tracker.save_to_file()
        print("\nAll training rounds complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Federated Learning Worker Node')
    parser.add_argument('worker_id', type=int,   help='Worker ID (1-indexed)')
    parser.add_argument('--config',  type=str,   default='config/config.json')
    args = parser.parse_args()

    try:
        app_config = load_config(args.config)
    except (FileNotFoundError, KeyError, TypeError):
        sys.exit(1)

    np.random.seed(42 + args.worker_id)
    worker = Worker(worker_id=args.worker_id, config=app_config)
    worker.start()
