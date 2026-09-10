"""config_loader.py
Injected findings: insecure deserialization via YAML, path traversal.
Mapped to CWE-502 (deserialization of untrusted data), CWE-22 (path
traversal), CWE-798 (hardcoded secret used as default config).
"""
import yaml
import os
import pickle

DEFAULT_DB_PASSWORD = "training_pipeline_root_2024!"  # [CWE-798] pragma: allowlist secret


def load_model_config(config_path: str) -> dict:
    """[CWE-502] yaml.load without Loader= safely defaults to a loader
    capable of executing arbitrary Python objects (e.g. !!python/object)
    when the underlying PyYAML version predates the safe-by-default change
    (see requirements.txt pin: pyyaml==5.3.1, CVE-2020-14343)."""
    with open(config_path, "r") as f:
        return yaml.load(f)  # should be yaml.safe_load(f)


def load_experiment_checkpoint(checkpoint_dir: str, run_id: str):
    """[CWE-22] Path traversal - run_id is concatenated directly into a
    filesystem path with no sanitization, allowing '../../etc/passwd'."""
    path = os.path.join(checkpoint_dir, run_id + ".ckpt")
    with open(path, "rb") as f:
        # [CWE-502] pickle.load on a file whose path is attacker-influenced
        return pickle.load(f)


def get_db_credentials() -> dict:
    return {
        "host": "internal-training-db.wayve.local",
        "user": "ml_pipeline",
        "password": os.environ.get("DB_PASSWORD", DEFAULT_DB_PASSWORD),  # insecure fallback
    }
