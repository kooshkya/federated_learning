import argparse
import sys
import threading
import time
from typing import Dict

import numpy as np
from scapy.all import sniff
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

        if Aggregation not in pkt:
            return

        agg = pkt[Aggregation]
        sender_id  = int(agg.worker_id)
        round_num  = int(agg.round_num)
        weight_idx = int(agg.weight_index)
        total      = int(agg.total_weights)
        SCALE      = 1_000_000

        if sender_id == self.worker_id or round_num != self.current_round:
            return

        if sender_id not in self.received_weights:
            self.received_weights[sender_id] = {
                "weights": np.zeros(total, dtype=np.float32),
                "received": 0,
                "total": total,
            }

        buf = self.received_weights[sender_id]
        buf["weights"][weight_idx] = int(agg.weight_value) / SCALE  # int() here too
        buf["received"] += 1

        num_workers      = self.config.protocol.num_workers
        expected_senders = num_workers - 1

        all_done = (
            len(self.received_weights) == expected_senders
            and all(b["received"] >= b["total"] for b in self.received_weights.values())
        )

        if all_done:
            my_flat    = np.concatenate([w.flatten() for w in self.model.get_weights()])
            peer_flats = [b["weights"] for b in self.received_weights.values()]
            averaged   = np.mean([my_flat] + peer_flats, axis=0)

            model  = self.model
            shapes = [model.W1.shape, model.b1.shape, model.W2.shape, model.b2.shape]
            new_weights = []
            offset = 0
            for shape in shapes:
                size = int(np.prod(shape))
                new_weights.append(averaged[offset:offset + size].reshape(shape))
                offset += size

            self.model.set_weights(new_weights)
            print(f"Worker {self.worker_id}: aggregated weights from {expected_senders} peer(s).")
            self.received_event.set()

    def send_model_weights(self):
        weights = self.model.get_weights()
        flat_weights = np.concatenate([w.flatten() for w in weights])
        total = len(flat_weights)
        SCALE = 1_000_000

        for idx, val in enumerate(flat_weights):
            # Cast to plain Python int explicitly — numpy.int64 breaks Scapy's IntField
            weight_int = int(round(float(val) * SCALE))

            pkt = (
                Ether(dst="ff:ff:ff:ff:ff:ff", type=TYPE_AGGREGATION)
                / Aggregation(
                    round_num=self.current_round,
                    worker_id=self.worker_id,
                    weight_index=idx,
                    total_weights=total,
                    weight_value=weight_int,
                )
            )

            sendp(pkt, iface=self.iface, verbose=False)

        print(f"Worker {self.worker_id}: sent {total} weight packets for round {self.current_round + 1}")


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
        self.send_model_weights()
        print("Waiting for aggregated model from server...")
        self.received_event.wait()
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

    try:
        app_config = load_config(args.config)
    except (FileNotFoundError, KeyError, TypeError):
        sys.exit(1)

    np.random.seed(42 + args.worker_id)

    worker = Worker(worker_id=args.worker_id, config=app_config)
    worker.start()
