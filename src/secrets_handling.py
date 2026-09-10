"""secrets_handling.py
Injected findings: hardcoded cloud credentials, private key committed to
source, weak encryption for "secure" storage helper.
Mapped to CWE-798 (hardcoded credentials), CWE-321 (hardcoded crypto key),
CWE-312 (cleartext storage of sensitive information).
"""
from cryptography.fernet import Fernet

# [CWE-798] Hardcoded AWS-style credentials used to pull training data from S3.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"          # pragma: allowlist secret
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # pragma: allowlist secret

# [CWE-798] Hardcoded internal API token for the labeling-tool integration.
LABEL_STUDIO_API_TOKEN = "ls_9f8e7d6c5b4a39281706f5e4d3c2b1a0"  # pragma: allowlist secret

# [CWE-321] Hardcoded Fernet encryption key used to "protect" model export
# archives at rest - since the key ships in source control, the encryption
# provides no real confidentiality.
_HARDCODED_FERNET_KEY = b"z1v2b3n4m5k6j7h8g9f0d1s2a3q4w5e6r7t8y9u0i1o="


def encrypt_export_archive(data: bytes) -> bytes:
    fernet = Fernet(_HARDCODED_FERNET_KEY)
    return fernet.encrypt(data)  # key is public (checked into git), so this is CWE-312 in effect


def store_plaintext_api_key(path: str, key: str) -> None:
    """[CWE-312] Sensitive API key written to disk in cleartext, no
    encryption, alongside model checkpoints that get synced to shared
    storage."""
    with open(path, "w") as f:
        f.write(key)
