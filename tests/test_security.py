import pytest
from cryptography.exceptions import InvalidTag

from dimos_adapter.models import DeviceManifest
from dimos_adapter.security import (
    Identity,
    ReplayError,
    SecureChannel,
    derive_session_key,
    pairing_proof,
    verify_manifest,
    verify_pairing_proof,
)


def test_signed_manifest_detects_tampering() -> None:
    identity = Identity.generate("device")
    manifest = DeviceManifest(
        device_id="device",
        display_name="Audio",
        adapter_version="0.1.0",
        boot_id="boot",
        signing_public_key=identity.signing_public,
        exchange_public_key=identity.exchange_public,
    )
    signed = identity.sign_manifest(manifest)

    assert verify_manifest(signed)
    signed.manifest.display_name = "tampered"
    assert not verify_manifest(signed)


def test_pairing_proof_binds_controller_and_nonce() -> None:
    arguments = {
        "device_id": "device",
        "controller_id": "controller",
        "nonce": "nonce",
        "controller_exchange_public": "public",
    }
    proof = pairing_proof("secret", **arguments)

    assert verify_pairing_proof("secret", proof, **arguments)
    assert not verify_pairing_proof("wrong", proof, **arguments)


def test_secure_channel_encrypts_and_rejects_replay_and_tampering() -> None:
    device = Identity.generate("device")
    controller = Identity.generate("controller")
    device_key = derive_session_key(
        device.exchange_private,
        controller.exchange_public,
        device_id="device",
        controller_id="controller",
    )
    controller_key = derive_session_key(
        controller.exchange_private,
        device.exchange_public,
        device_id="device",
        controller_id="controller",
    )
    sender = SecureChannel(device_key, "audio", nonce_prefix=b"test")
    receiver = SecureChannel(controller_key, "audio")
    envelope = sender.encrypt(b"hello")

    assert receiver.decrypt(envelope) == b"hello"
    with pytest.raises(ReplayError):
        receiver.decrypt(envelope)

    fresh_receiver = SecureChannel(controller_key, "audio")
    tampered = envelope[:-1] + bytes([envelope[-1] ^ 1])
    with pytest.raises(InvalidTag):
        fresh_receiver.decrypt(tampered)
