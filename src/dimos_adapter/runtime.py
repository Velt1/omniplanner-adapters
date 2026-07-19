"""Zenoh discovery, pairing, control and encrypted audio runtime."""

from __future__ import annotations

import base64
import json
import threading
import uuid
from typing import Any

import zenoh

from dimos_adapter import __version__
from dimos_adapter.models import DISCOVERY_INTERVAL_SECONDS, AudioFrame, DeviceManifest
from dimos_adapter.security import (
    SecureChannel,
    canonical_json,
    derive_session_key,
    verify_pairing_proof,
)
from dimos_adapter.state import AdapterState

DISCOVERY_PREFIX = "dimos/adapters/v1/discovery"
PAIR_PREFIX = "dimos/adapters/v1/pair"
SESSION_PREFIX = "dimos/adapters/v1/session"


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
        self._subscribers: list[Any] = []
        self._channels: dict[str, dict[str, SecureChannel]] = {}
        self._audio_started = False

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
        self._subscribers.append(
            self._session.declare_subscriber(
                f"{PAIR_PREFIX}/{self.identity.device_id}/request",
                self._on_pair_request,
            )
        )
        for controller_id, pairing in self.state.pairings().items():
            self._setup_controller(controller_id, pairing["exchange_public_key"])
        self._heartbeat = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat.start()

    @staticmethod
    def _sample_bytes(sample: Any) -> bytes:
        return sample.payload.to_bytes()

    def _on_pair_request(self, sample: Any) -> None:
        assert self._session is not None
        try:
            request = json.loads(self._sample_bytes(sample))
            token = self.state.active_token()
            proof_fields = {
                "device_id": self.identity.device_id,
                "controller_id": request["controller_id"],
                "nonce": request["nonce"],
                "controller_exchange_public": request["controller_exchange_public"],
            }
            accepted = token is not None and verify_pairing_proof(
                token.value,
                request["proof"],
                **proof_fields,
            )
            if accepted:
                self.state.save_pairing(
                    request["controller_id"],
                    {
                        "exchange_public_key": request["controller_exchange_public"],
                        "display_name": request.get("controller_name", request["controller_id"]),
                    },
                )
                self.state.consume_active_token()
                self._setup_controller(
                    request["controller_id"],
                    request["controller_exchange_public"],
                )
            response = {
                "accepted": accepted,
                "device_id": self.identity.device_id,
                "controller_id": request["controller_id"],
                "nonce": request["nonce"],
                "device_exchange_public": self.identity.exchange_public,
            }
            signature = self.identity.signing_private.sign(canonical_json(response))
            response["signature"] = base64.urlsafe_b64encode(signature).decode()
            self._session.put(
                f"{PAIR_PREFIX}/{self.identity.device_id}/response/{request['controller_id']}",
                canonical_json(response),
            )
        except Exception:
            return

    def _setup_controller(self, controller_id: str, exchange_public: str) -> None:
        assert self._session is not None
        if controller_id in self._channels:
            return
        key = derive_session_key(
            self.identity.exchange_private,
            exchange_public,
            device_id=self.identity.device_id,
            controller_id=controller_id,
        )
        self._channels[controller_id] = {
            "control_request": SecureChannel(key, "control/request"),
            "control_response": SecureChannel(key, "control/response"),
            "microphone": SecureChannel(key, "audio/microphone"),
            "speaker": SecureChannel(key, "audio/speaker"),
        }
        base = f"{SESSION_PREFIX}/{self.identity.device_id}/{controller_id}"
        self._subscribers.append(
            self._session.declare_subscriber(
                f"{base}/control/request",
                lambda sample, cid=controller_id: self._on_control(cid, sample),
            )
        )
        self._subscribers.append(
            self._session.declare_subscriber(
                f"{base}/audio/speaker",
                lambda sample, cid=controller_id: self._on_speaker(cid, sample),
            )
        )

    def _on_control(self, controller_id: str, sample: Any) -> None:
        assert self._session is not None
        try:
            channels = self._channels[controller_id]
            request = json.loads(channels["control_request"].decrypt(self._sample_bytes(sample)))
            audio = self.capabilities[0]
            action = request["action"]
            if action == "audio.acquire":
                result: Any = {"acquired": audio.acquire(controller_id)}
                if result["acquired"] and not self._audio_started:
                    audio.start_microphone(self._publish_microphone)
                    self._audio_started = True
            elif action == "audio.release":
                audio.release(controller_id)
                result = {"released": True}
            elif action == "session_status":
                result = audio.session_status()
            else:
                result = {"error": f"unknown action: {action}"}
            response = canonical_json({"request_id": request["request_id"], "result": result})
            self._session.put(
                f"{SESSION_PREFIX}/{self.identity.device_id}/{controller_id}/control/response",
                channels["control_response"].encrypt(response),
            )
        except Exception:
            return

    def _publish_microphone(self, frame: AudioFrame) -> None:
        assert self._session is not None
        owner = self.capabilities[0].session_status().get("owner")
        if owner is None or owner not in self._channels:
            return
        self._session.put(
            f"{SESSION_PREFIX}/{self.identity.device_id}/{owner}/audio/microphone",
            self._channels[owner]["microphone"].encrypt(frame.to_bytes()),
        )

    def _on_speaker(self, controller_id: str, sample: Any) -> None:
        try:
            if self.capabilities[0].session_status().get("owner") != controller_id:
                return
            plaintext = self._channels[controller_id]["speaker"].decrypt(self._sample_bytes(sample))
            self.capabilities[0].play(AudioFrame.from_bytes(plaintext))
        except Exception:
            return

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
        for subscriber in self._subscribers:
            subscriber.undeclare()
        self._subscribers.clear()
        if self._session is not None:
            self._session.close()
        self._session = None
