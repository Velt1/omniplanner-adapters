"""Zenoh discovery runtime used by capability adapters."""

from __future__ import annotations

import json
import threading
import uuid
from typing import Any

import zenoh

from dimos_adapter import __version__
from dimos_adapter.models import DISCOVERY_INTERVAL_SECONDS, DeviceManifest
from dimos_adapter.security import canonical_json
from dimos_adapter.state import AdapterState

DISCOVERY_PREFIX = "dimos/adapters/v1/discovery"


def zenoh_config(connect: list[str] | None = None) -> zenoh.Config:
    config = zenoh.Config()
    config.insert_json5("mode", '"peer"')
    if connect:
        config.insert_json5("connect/endpoints", json.dumps(connect))
    return config


class AdapterRuntime:
    def __init__(self, state: AdapterState, capabilities: list[Any], connect: list[str]) -> None:
        self.state = state
        self.identity = state.identity()
        self.capabilities = capabilities
        self.connect = connect
        self.boot_id = uuid.uuid4().hex
        self._session: zenoh.Session | None = None
        self._stop = threading.Event()
        self._heartbeat: threading.Thread | None = None
        self._sequence = 0

    def manifest(self) -> DeviceManifest:
        return DeviceManifest(
            device_id=self.identity.device_id,
            display_name=self.state.display_name(),
            adapter_version=__version__,
            boot_id=self.boot_id,
            sequence=self._sequence,
            signing_public_key=self.identity.signing_public,
            exchange_public_key=self.identity.exchange_public,
            paired_controllers=len(self.state.pairings()),
            capabilities=[capability.manifest for capability in self.capabilities],
        )

    def start(self) -> None:
        self._session = zenoh.open(zenoh_config(self.connect))
        self._heartbeat = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat.start()

    def _heartbeat_loop(self) -> None:
        assert self._session is not None
        publisher = self._session.declare_publisher(f"{DISCOVERY_PREFIX}/{self.identity.device_id}")
        try:
            while not self._stop.is_set():
                self._sequence += 1
                signed = self.identity.sign_manifest(self.manifest())
                publisher.put(canonical_json(signed.model_dump(mode="json")))
                self._stop.wait(DISCOVERY_INTERVAL_SECONDS)
        finally:
            publisher.undeclare()

    def run_forever(self) -> None:
        self.start()
        try:
            while not self._stop.wait(1.0):
                pass
        finally:
            self.stop()

    def stop(self) -> None:
        self._stop.set()
        if self._heartbeat is not None and self._heartbeat.is_alive():
            self._heartbeat.join(timeout=3.0)
        for capability in self.capabilities:
            capability.stop()
        if self._session is not None:
            self._session.close()
        self._session = None
