import argparse
import sys
import threading
import time
from collections import defaultdict
from typing import Dict, List

import numpy as np
from scapy.all import Ether, sendp, sniff
from scapy.packet import Packet

from config.config import AppConfig, load_config
from ml.data_loader import load_multi_mnist
from ml.model import SimpleNeuralNetwork
from protocol.layers import Aggregation, TYPE_AGGREGATION, SCALE_FACTOR
from utils.network import get_if
from utils.tracker import ResultsTracker

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
# Buffer: round -> worker_id -> {index -> value}
RecvBuffer = Dict[int, Dict[int, Dict[int, int]]]


class Worker:
    def __init__(self, worker_id: int, config: AppConfig):
        self.worker_id  = worker_id
        self.config     = config
        self.iface      = get_if()
        self.num_workers = config.protocol.num_workers

        self.results_tracker = ResultsTracker(worker_id)
        self.model = SimpleNeuralNetwork(
            input_size=self.config.model_params.input_size,
            hidden_size=self.config.model_params.hidden_size,
            output_size=self.config.model_params.output_size,
        )

        # received_weights[round][worker_id] = flat np.ndarray once complete
        self.received_weights: Dict[int, Dict[int, np.ndarray]] = defaultdict(dict)
        # buffer for in-progress reception
        self._recv_buf: RecvBuffer = defaultdict(lambda: defaultdict(dict))
        self._recv_totals: Dict[int, Dict[int, int]] = defaultdict(dict)  # round->wid->total

        self._round_done_event = threading.Event()
        self.current_round = 0

        self._lock = threading.Lock()

        self.receiver_thread = threading.Thread(target=self._packet_receiver, daemon=True)
        self.receiver_thread.start()

    # ------------------------------------------------------------------
    # Networking
    # ------------------------------------------------------------------

    def _packet_receiver(self):
        print(f"[Worker {self.worker_id}] Listening on {self.iface} for aggregation packets...")
        try:
            sniff(
                filter="ether proto 0x1234",
                iface=self.iface,
                prn=self._handle_packet,
            )
        except Exception as e:
            print(f"[Worker {self.worker_id}] Receiver error: {e}", file=sys.stderr)

    def _handle_packet(self, pkt: Packet):
        if not pkt.haslayer(Aggregation):
            return

        agg = pkt[Aggregation]
        round_num    = agg.round_num
        sender_id    = agg.worker_id
        idx          = agg.weight_index
        total        = agg.total_weights
        raw_val      = agg.weight_value

        # Ignore our own packets (we add our own weights locally)
        if sender_id == self.worker_id:
            return

        with self._lock:
            self._recv_buf[round_num][sender_id][idx] = raw_val
            self._recv_totals[round_num][sender_id]   = total

            # Check if this sender's weights are now complete for this round
            if (sender_id not in self.received_weights[round_num] and
                    len(self._recv_buf[round_num][sender_id]) == total):
                flat = np.array(
                    [self._recv_buf[round_num][sender_id][i] for i in range(total)],
                    dtype=np.float64
                ) / SCALE_FACTOR
                self.received_weights[round_num][sender_id] = flat
                print(f"[Worker {self.worker_id}] Got complete weights from worker "
                      f"{sender_id} for round {round_num}")

            # Signal if we have weights from ALL other workers for the current round
            others_needed = self.num_workers - 1
            if len(self.received_weights.get(self.current_round, {})) >= others_needed:
                self._round_done_event.set()

    def send_model_weights(self):
        """Broadcast this worker's current weights one-weight-per-packet."""
        weights      = self.model.get_weights()
        flat_weights = np.concatenate([w.flatten() for w in weights])
        total        = len(flat_weights)

        print(f"[Worker {self.worker_id}] Sending {total} weight packets for "
              f"round {self.current_round}...")

        for idx, val in enumerate(flat_weights):
            raw_val = int(round(float(val) * SCALE_FACTOR))
            # Clamp to int32 range (should never be needed given [-0.5, 0.5])
            raw_val = max(-2_147_483_648, min(2_147_483_647, raw_val))

            pkt = (
                Ether(dst=BROADCAST_MAC, type=TYPE_AGGREGATION)
                / Aggregation(
                    round_num=self.current_round & 0xFF,
                    worker_id=self.worker_id & 0xFF,
                    weight_index=idx,
                    total_weights=total,
                    weight_value=raw_val,
                )
            )
            sendp(pkt, iface=self.iface, verbose=False)

        print(f"[Worker {self.worker_id}] Done sending weights.")

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------

    def _wait_for_all_weights(self, timeout: float = 120.0):
        """Block until we have received weights from all other workers."""
        deadline = time.time() + timeout
        while True:
            self._round_done_event.wait(timeout=1.0)
            with self._lock:
                have = len(self.received_weights.get(self.current_round, {}))
            if have >= self.num_workers - 1:
                self._round_done_event.clear()
                return True
            if time.time() > deadline:
                print(f"[Worker {self.worker_id}] Timeout waiting for weights "
                      f"in round {self.current_round}!", file=sys.stderr)
                self._round_done_event.clear()
                return False

    def _federated_average(self) -> List[np.ndarray]:
        """Average own weights with all received weights."""
        own_weights = self.model.get_weights()
        own_flat    = np.concatenate([w.flatten() for w in own_weights])

        all_flats = [own_flat]
        with self._lock:
            for sender_id, flat in self.received_weights[self.current_round].items():
                all_flats.append(flat)

        avg_flat = np.mean(all_flats, axis=0)

        # Reconstruct into original shapes
        sizes  = [w.size for w in own_weights]
        shapes = [w.shape for w in own_weights]
        result = []
        offset = 0
        for size, shape in zip(sizes, shapes):
            result.append(avg_flat[offset:offset + size].reshape(shape))
            offset += size
        return result

    # ------------------------------------------------------------------
    # Main training loop
    # ------------------------------------------------------------------

    def run(self, X_train, y_train):
        cfg = self.config.training
        for round_num in range(cfg.rounds):
            self.current_round = round_num
            print(f"\n[Worker {self.worker_id}] === Round {round_num + 1}/{cfg.rounds} ===")

            # 1. Local training
            self.model.train(
                X_train, y_train,
                epochs=cfg.epochs_per_round,
                learning_rate=cfg.learning_rate,
                momentum=cfg.momentum,
            )

            loss     = self.model.compute_loss(
                np.eye(self.config.model_params.output_size)[y_train],
                self.model.forward(X_train)
            )
            accuracy = self.model.evaluate(X_train, y_train)
            self.results_tracker.add_round_results(round_num + 1, loss, accuracy)
            print(f"[Worker {self.worker_id}] Local — Loss: {loss:.4f}, Acc: {accuracy:.4f}")

            # 2. Broadcast weights
            self.send_model_weights()

            # 3. Wait for all other workers' weights
            success = self._wait_for_all_weights(timeout=120.0)
            if not success:
                print(f"[Worker {self.worker_id}] Skipping aggregation due to timeout.")
                continue

            # 4. Federated average and update model
            averaged_weights = self._federated_average()
            self.model.set_weights(averaged_weights)
            print(f"[Worker {self.worker_id}] Applied federated average.")

        self.results_tracker.save_to_file()
        print(f"\n[Worker {self.worker_id}] Training complete.")


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Federated Learning Worker")
    parser.add_argument("--worker-id", type=int, required=True,
                        help="Worker ID (1, 2, or 3)")
    parser.add_argument("--config",    type=str,
                        default="src/config/config.json",
                        help="Path to config JSON")
    args = parser.parse_args()

    config = load_config(args.config)
    digits_map = {1: (3, 8), 2: (1, 7), 3: (0, 4)}  # different digit pairs per worker
    digits = digits_map.get(args.worker_id, (3, 8))

    (X_train, y_train), _ = load_multi_mnist(
        digits=digits,
        num_features=config.model_params.input_size,
        num_samples=config.training.samples_per_worker * config.protocol.num_workers,
        num_workers=config.protocol.num_workers,
    )

    worker = Worker(worker_id=args.worker_id, config=config)
    worker.run(X_train, y_train)


if __name__ == "__main__":
    main()
