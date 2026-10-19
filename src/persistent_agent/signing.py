"""Versioned Ed25519 verification; private keys stay with the host/keystore."""
import base64
import binascii
import re

from .model import IdentityRecord, IdentityValidationError

DOMAIN = b"Agent-Live identity snapshot ed25519-v1\x00"


def signature_payload(record: IdentityRecord) -> bytes:
    """Bytes for an external signer; v1 state hashes themselves are unchanged.

    signed_at is excluded by the existing canonical encoding. It is informational,
    not an authenticated timestamp. Retain revision/hash checkpoints for freshness.
    """
    return DOMAIN + record.canonical_bytes()


def verify_signature(record: IdentityRecord, *, expected_public_key: str) -> None:
    """Authenticate against host-pinned key material, never self-declared trust."""
    record.validate_core_invariants()
    if not isinstance(expected_public_key, str) or not re.fullmatch(r"ed25519:[0-9a-f]{64}", expected_public_key):
        raise IdentityValidationError("invalid host-pinned Ed25519 public key")
    identity = record.data["agent_identity"]
    if identity["cryptographic_identity"].get("public_key") != expected_public_key:
        raise IdentityValidationError("record key does not match host-pinned key")
    signature = identity["integrity"].get("signature")
    if not isinstance(signature, str) or not signature.startswith("ed25519-v1:"):
        raise IdentityValidationError("missing or unsupported signature encoding")
    try:
        raw = base64.b64decode(signature[len("ed25519-v1:"):], validate=True)
        if len(raw) != 64:
            raise ValueError("invalid signature length")
    except (ValueError, binascii.Error) as exc:
        raise IdentityValidationError("invalid signature encoding") from exc
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise IdentityValidationError("signature verification requires persistent-agent[signing]") from exc
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(expected_public_key[8:])).verify(raw, signature_payload(record))
    except InvalidSignature as exc:
        raise IdentityValidationError("identity signature verification failed") from exc
