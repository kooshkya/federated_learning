import json
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class ProtocolConfig:
    num_workers: int


@dataclass
class TrainingConfig:
    rounds: int
    samples_per_worker: int
    epochs_per_round: int
    learning_rate: float
    momentum: float

@dataclass
class ModelParamsConfig:
    input_size: int
    hidden_size: int
    output_size: int

@dataclass
class AppConfig:
    protocol: ProtocolConfig
    training: TrainingConfig
    model_params: ModelParamsConfig

    @classmethod
    def from_dict(cls, cfg: Dict[str, Any]) -> 'AppConfig':
        return cls(
            protocol=ProtocolConfig(**cfg['protocol']),
            training=TrainingConfig(**cfg['training']),
            model_params=ModelParamsConfig(**cfg['model_params'])
        )


def load_config(path: str) -> AppConfig:
    try:
        with open(path, 'r') as f:
            config_dict = json.load(f)

        return AppConfig.from_dict(config_dict)

    except FileNotFoundError:
        print(f"Error: Configuration file '{path}' not found.")
        raise
    except (KeyError, TypeError) as e:
        print(f"Error: Configuration file '{path}' is malformed. Missing or incorrect key: {e}")
        raise
