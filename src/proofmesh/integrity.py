"""Optional Ed25519 signing and verification of evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from proofmesh.evidence import _canonical_json, sha256_bytes


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a new Ed25519 key pair (private PEM, public PEM)."""
    private = Ed25519PrivateKey.generate()
    priv_pem = private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_pem = private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem


def sign_evidence(evidence: dict[str, Any], private_key_pem: bytes) -> dict[str, Any]:
    """Sign the canonical evidence body. Returns evidence with integrity.signed=True."""
    private = load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise TypeError("Only Ed25519 private keys are supported")

    body = {k: v for k, v in evidence.items() if k != "integrity"}
    integrity = dict(evidence.get("integrity") or {})
    payload = {
        "content_hash": integrity.get("content_hash"),
        "body": body,
    }
    message = _canonical_json(payload)
    signature = private.sign(message)
    public = private.public_key()
    pub_bytes = public.public_bytes(Encoding.Raw, PublicFormat.Raw)

    integrity["signed"] = True
    integrity["signature"] = signature.hex()
    integrity["algorithm"] = "ed25519"
    integrity["public_key_hint"] = sha256_bytes(pub_bytes)[:16]
    integrity["note"] = (
        "Ed25519 signature over canonical body + content_hash. "
        "Verify with the corresponding public key."
    )

    result = dict(evidence)
    result["integrity"] = integrity
    return result


def verify_signature(evidence: dict[str, Any], public_key_pem: bytes) -> tuple[bool, str]:
    """Verify Ed25519 signature on evidence. Returns (ok, message)."""
    integrity = evidence.get("integrity") or {}
    if not integrity.get("signed"):
        return False, "Evidence is not marked as signed"
    sig_hex = integrity.get("signature")
    if not sig_hex:
        return False, "Missing signature"

    public = load_pem_public_key(public_key_pem)
    if not isinstance(public, Ed25519PublicKey):
        raise TypeError("Only Ed25519 public keys are supported")

    body = {k: v for k, v in evidence.items() if k != "integrity"}
    payload = {
        "content_hash": integrity.get("content_hash"),
        "body": body,
    }
    message = _canonical_json(payload)
    try:
        public.verify(bytes.fromhex(sig_hex), message)
        return True, "Signature valid"
    except (InvalidSignature, ValueError) as exc:
        return False, f"Signature verification failed: {exc}"


def save_keypair(private_pem: bytes, public_pem: bytes, directory: Path) -> None:
    """Write key pair to directory (caller must protect private key permissions)."""
    directory.mkdir(parents=True, exist_ok=True)
    priv_path = directory / "proofmesh_ed25519.pem"
    pub_path = directory / "proofmesh_ed25519.pub.pem"
    priv_path.write_bytes(private_pem)
    pub_path.write_bytes(public_pem)
    try:
        priv_path.chmod(0o600)
    except OSError:
        pass
