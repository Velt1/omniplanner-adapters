from dimos_adapter.models import AudioFrame, DeviceManifest


def test_audio_frame_round_trip_preserves_pcm_contract() -> None:
    source = AudioFrame(7, 123456, b"\x01\x02" * 320)

    decoded = AudioFrame.from_bytes(source.to_bytes())

    assert decoded == source


def test_manifest_rejects_unknown_fields() -> None:
    payload = {
        "device_id": "device",
        "display_name": "Audio",
        "adapter_version": "0.1.0",
        "boot_id": "boot",
        "signing_public_key": "key",
        "exchange_public_key": "key",
        "unexpected": True,
    }

    try:
        DeviceManifest.model_validate(payload)
    except ValueError as exc:
        assert "unexpected" in str(exc)
    else:
        raise AssertionError("unknown fields must be rejected")
