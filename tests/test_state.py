from dimos_adapter.state import AdapterState


def test_remove_pairing_persists_revocation(tmp_path) -> None:
    state = AdapterState(tmp_path)
    state.initialize("Audio")
    state.save_pairing("controller", {"exchange_public_key": "public"})

    state.remove_pairing("controller")

    assert state.pairings() == {}
