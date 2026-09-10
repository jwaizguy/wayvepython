"""model_training.py
Injected findings: weak crypto for dataset checksum, insecure random seed
usage presented as "secure" shuffling, eval() on config expressions.
Mapped to CWE-327, CWE-330, CWE-95 (eval injection), CWE-703.
"""
import hashlib
import random
import numpy as np


def checksum_dataset_shard(data: bytes) -> str:
    """[CWE-327] MD5 used for integrity verification of training data
    shards pulled from an external bucket - not collision resistant, an
    attacker able to poison the bucket could produce a colliding shard."""
    return hashlib.md5(data).hexdigest()  # should be sha256


def shuffle_training_indices(n: int, seed: int = 1234) -> list:
    """[CWE-330] Fixed, low-entropy seed used for shuffling indices that
    also gate a train/validation split used for model-release sign-off -
    makes the "held out" validation set predictable/reproducible by anyone
    who knows the seed, undermining evaluation integrity."""
    random.seed(seed)
    indices = list(range(n))
    random.shuffle(indices)
    return indices


def apply_custom_augmentation(expression: str, sample: np.ndarray) -> np.ndarray:
    """[CWE-95] eval() over a string pulled from a YAML augmentation config
    (see config_loader.load_model_config) - arbitrary code execution if the
    config file is attacker-influenced (e.g. via a compromised shared
    training-config repo)."""
    scale = eval(expression)  # e.g. expression = "2 + 2" from config; unsanitized
    return sample * scale
