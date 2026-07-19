"""Persistent identities, pairing proofs, signatures and replay-safe encryption."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from dimos_adapter.models import DeviceManifest, SignedManifest


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@dataclass(slots=True)
class Identity:
    device_id: str
    signing_private: Ed25519PrivateKey
    exchange_private: X25519PrivateKey

    @classmethod
    def generate(cls, device_id: str | None = None) -> Identity:
        return cls(
            device_id or secrets.token_hex(16),
            Ed25519PrivateKey.generate(),
            X25519PrivateKey.generate(),
        )

    @property
    def signing_public(self) -> str:
        return _b64(
            self.signing_private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        )

    @property
    def exchange_public(self) -> str:
        return _b64(
            self.exchange_private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "device_id": self.device_id,
            "signing_private": _b64(
                self.signing_private.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            ),
            "exchange_private": _b64(
                self.exchange_private.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            ),
        }
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2))
        os.chmod(temporary, 0o600)
        temporary.replace(path)

    @classmethod
    def load(cls, path: Path) -> Identity:
        payload = json.loads(path.read_text())
        return cls(
            payload["device_id"],
            Ed25519PrivateKey.from_private_bytes(_unb64(payload["signing_private"])),
            X25519PrivateKey.from_private_bytes(_unb64(payload["exchange_private"])),
        )

    def sign_manifest(self, manifest: DeviceManifest) -> SignedManifest:
        signature = self.signing_private.sign(canonical_json(manifest.model_dump(mode="json")))
        return SignedManifest(manifest=manifest, signature=_b64(signature))


def verify_manifest(signed: SignedManifest) -> bool:
    try:
        public = Ed25519PublicKey.from_public_bytes(_unb64(signed.manifest.signing_public_key))
        public.verify(
            _unb64(signed.signature),
            canonical_json(signed.manifest.model_dump(mode="json")),
        )
    except (InvalidSignature, ValueError):
        return False
    return True


@dataclass(frozen=True, slots=True)
class EnrollmentToken:
    value: str
    expires_at: float

    @classmethod
    def create(cls, lifetime_seconds: float = 600.0) -> EnrollmentToken:
        return cls(_b64(secrets.token_bytes(24)), time.time() + lifetime_seconds)

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at


def pairing_proof(
    token: str,
    *,
    device_id: str,
    controller_id: str,
    nonce: str,
    controller_exchange_public: str,
) -> str:
    message = canonical_json(
        {
            "device_id": device_id,
            "controller_id": controller_id,
            "nonce": nonce,
            "controller_exchange_public": controller_exchange_public,
        }
    )
    return _b64(hmac.new(token.encode(), message, hashlib.sha256).digest())


def verify_pairing_proof(token: str, supplied: str, **kwargs: str) -> bool:
    expected = pairing_proof(token, **kwargs)
    return hmac.compare_digest(expected, supplied)


def derive_session_key(
    private_key: X25519PrivateKey,
    peer_public: str,
    *,
    device_id: str,
    controller_id: str,
) -> bytes:
    shared = private_key.exchange(X25519PublicKey.from_public_bytes(_unb64(peer_public)))
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"dimos-adapter/v1/{device_id}/{controller_id}".encode(),
    ).derive(shared)


class ReplayError(ValueError):
    pass


class SecureChannel:
    """AES-GCM channel with monotonic sequence replay protection."""

    def __init__(self, key: bytes, channel: str, *, nonce_prefix: bytes | None = None) -> None:
        if len(key) != 32:
            raise ValueError("AES-256 key must contain 32 bytes")
        self._aead = AESGCM(key)
        self._channel = channel.encode()
        self._prefix = nonce_prefix or secrets.token_bytes(4)
        if len(self._prefix) != 4:
            raise ValueError("nonce_prefix must contain 4 bytes")
        self._send_sequence = 0
        self._received_sequences: dict[bytes, int] = {}

    def encrypt(self, payload: bytes) -> bytes:
        self._send_sequence += 1
        sequence = self._send_sequence
        nonce = self._prefix + sequence.to_bytes(8, "big")
        ciphertext = self._aead.encrypt(nonce, payload, self._channel)
        return nonce + ciphertext

    def decrypt(self, envelope: bytes) -> bytes:
        if len(envelope) < 12 + 16:
            raise ValueError("truncated secure envelope")
        nonce, ciphertext = envelope[:12], envelope[12:]
        prefix, sequence = nonce[:4], int.from_bytes(nonce[4:], "big")
        if sequence <= self._received_sequences.get(prefix, 0):
            raise ReplayError("replayed or out-of-order secure envelope")
        plaintext = self._aead.decrypt(nonce, ciphertext, self._channel)
        self._received_sequences[prefix] = sequence
        return plaintext
