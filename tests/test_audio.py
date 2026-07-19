from dimos_adapter.audio import AudioCapability


def test_audio_session_is_exclusive_until_owner_releases() -> None:
    audio = AudioCapability()

    assert audio.acquire("robot-a")
    assert not audio.acquire("robot-b")
    assert audio.session_status() == {"active": True, "owner": "robot-a"}

    audio.release("robot-a")

    assert audio.acquire("robot-b")
