"""archive_extraction.py
[CWE-22] Zip-slip / path traversal on archive extraction - extracting a
downloaded model-checkpoint or dataset archive without validating that
each member's resolved path stays inside the destination directory lets a
malicious archive write files anywhere the process can reach (e.g.
overwriting a shared library or a cron file) via '../' entries.
"""
import tarfile
import zipfile


def extract_model_checkpoint_archive(archive_path: str, dest_dir: str) -> None:
    """tarfile.extractall() with no filter/validation - vulnerable to the
    classic zip-slip pattern (CVE-2007-4559-style) on crafted tar members
    such as '../../../../etc/cron.d/malicious'."""
    with tarfile.open(archive_path) as tar:
        tar.extractall(path=dest_dir)  # no member-path validation


def extract_dataset_zip(zip_path: str, dest_dir: str) -> None:
    """Same pattern via zipfile - member names are trusted as-is."""
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(path=dest_dir)  # no member-path validation
