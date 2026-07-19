"""Adapter configuration and pairing persistence."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from dimos_adapter.security import EnrollmentToken, Identity


def default_state_dir() -> Path:
    return (
        Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "dimos-adapter"
    )


class AdapterState:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or default_state_dir()
        self.identity_path = self.root / "identity.json"
        self.config_path = self.root / "config.json"
        self.pairings_path = self.root / "pairings.json"
        self.token_path = self.root / "enrollment.json"

    def initialize(self, display_name: str) -> Identity:
        self.root.mkdir(parents=True, exist_ok=True)
        identity = (
            Identity.load(self.identity_path)
            if self.identity_path.exists()
            else Identity.generate()
        )
        identity.save(self.identity_path)
        self._atomic_json(self.config_path, {"display_name": display_name})
        if not self.pairings_path.exists():
            self._atomic_json(self.pairings_path, {})
        return identity

    def identity(self) -> Identity:
        return Identity.load(self.identity_path)

    def display_name(self) -> str:
        return json.loads(self.config_path.read_text())["display_name"]

    def create_token(self) -> EnrollmentToken:
        token = EnrollmentToken.create()
        self._atomic_json(
            self.token_path,
            {"value": token.value, "expires_at": token.expires_at},
        )
        return token

    def consume_token(self, value: str) -> bool:
        if not self.token_path.exists():
            return False
        payload = json.loads(self.token_path.read_text())
        token = EnrollmentToken(payload["value"], payload["expires_at"])
        valid = not token.expired and token.value == value
        if valid:
            self.token_path.unlink(missing_ok=True)
        return valid

    def active_token(self) -> EnrollmentToken | None:
        if not self.token_path.exists():
            return None
        payload = json.loads(self.token_path.read_text())
        token = EnrollmentToken(payload["value"], payload["expires_at"])
        return None if token.expired else token

    def consume_active_token(self) -> None:
        self.token_path.unlink(missing_ok=True)

    def pairings(self) -> dict[str, dict[str, Any]]:
        if not self.pairings_path.exists():
            return {}
        return json.loads(self.pairings_path.read_text())

    def save_pairing(self, controller_id: str, pairing: dict[str, Any]) -> None:
        pairings = self.pairings()
        pairings[controller_id] = pairing
        self._atomic_json(self.pairings_path, pairings)

    def _atomic_json(self, path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True))
        os.chmod(temporary, 0o600)
        temporary.replace(path)
