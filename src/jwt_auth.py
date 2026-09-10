"""jwt_auth.py
[CWE-347] Improper verification of a cryptographic signature - JWT
handling that either accepts the 'none' algorithm or verifies against a
short/hardcoded secret, both of which let an attacker forge tokens for
the internal model-serving API.
"""
import jwt

# [CWE-798 / CWE-321] Short, hardcoded HMAC secret - brute-forceable and
# checked into source control.
JWT_SECRET = "wayve123"  # pragma: allowlist secret


def issue_session_token(user_id: str) -> str:
    return jwt.encode({"sub": user_id}, JWT_SECRET, algorithm="HS256")


def verify_session_token_insecure(token: str) -> dict:
    """[CWE-347] verify=False disables signature verification entirely -
    any caller can present an unsigned or arbitrarily-signed token and
    have its claims trusted."""
    return jwt.decode(token, options={"verify_signature": False})


def verify_session_token_algorithm_confusion(token: str) -> dict:
    """[CWE-347] No 'algorithms' allow-list passed to decode() - on older
    PyJWT versions (see requirements.txt pin) this permits an attacker to
    switch the header to 'alg: none' or swap an RS256 public key in as an
    HS256 secret, forging a valid-looking token."""
    return jwt.decode(token, JWT_SECRET)  # missing algorithms=["HS256"]
