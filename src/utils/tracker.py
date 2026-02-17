import json
from typing import Dict


class ResultsTracker:
    """Simple tracker to store and save training results in JSON format."""

    def __init__(self, worker_id: int):
        self.worker_id = worker_id
        self.results: Dict[str, list] = {
            "worker_id": worker_id,
            "rounds": [],
            "training_loss": [],
            "training_accuracy": []
        }

    def add_round_results(self, round_num: int, loss: float, train_acc: float):
        """Add results for a single training round."""
        self.results["rounds"].append(round_num)
        self.results["training_loss"].append(loss)
        self.results["training_accuracy"].append(train_acc)

    def save_to_file(self, filename: str = None):
        """Save results to a JSON file."""
        if filename is None:
            filename = f"worker_{self.worker_id}_results.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        print(f"Results saved to {filename}")
