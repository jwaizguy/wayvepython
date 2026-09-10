"""data_loader.py
Injected findings: insecure deserialization of model/dataset artifacts,
SSRF via unchecked dataset URL fetch, insecure temp file handling.
Mapped to CWE-502, CWE-918 (SSRF), CWE-377 (insecure temp file),
CWE-020 (improper input validation).
"""
import pickle
import requests
import tempfile
import torch


def load_pretrained_weights(weights_path: str):
    """[CWE-502] torch.load defaults to pickle-based deserialization; a
    maliciously crafted .pt file can execute arbitrary code on load. No
    `weights_only=True` / trusted-source check applied here (CVE-adjacent
    to the torch==1.4.0 pin in requirements.txt)."""
    return torch.load(weights_path)  # unsafe default deserialization


def download_dataset_shard(url: str, dest_dir: str = "/tmp") -> str:
    """[CWE-918] Server-Side Request Forgery - url is taken directly from
    a user-supplied dataset manifest with no allow-list / scheme check,
    so an attacker can point this at internal metadata endpoints
    (e.g. http://169.254.169.254/) from within the training cluster."""
    response = requests.get(url, timeout=30)  # no allow-list, no scheme restriction
    fd, temp_path = tempfile.mkstemp(dir=dest_dir)  # [CWE-377] predictable perms/location
    with open(temp_path, "wb") as f:
        f.write(response.content)
    return temp_path


def load_labeled_annotations(pickle_path: str):
    """[CWE-502] Direct pickle.load of an annotation cache file that is
    regenerated from a shared network drive - trivially poisonable by
    anyone with write access to that share."""
    with open(pickle_path, "rb") as f:
        return pickle.load(f)
