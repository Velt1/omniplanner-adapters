"""Sounddevice-backed reference implementation of dimos.audio.duplex/v1."""

from __future__ import annotations

import queue
import threading
import time
from collections.abc import Callable
from typing import Any

import numpy as np

from dimos_adapter.models import (
    AUDIO_CONTRACT,
    ActionManifest,
    AudioFrame,
    CapabilityManifest,
    StreamManifest,
)


class AudioCapability:
    """Low-latency speech audio with an exclusive controller lease."""

    sample_rate = 16_000
    channels = 1
    block_size = 320

    def __init__(
        self,
        *,
        input_device: int | None = None,
        output_device: int | None = None,
    ) -> None:
        self.input_device = input_device
        self.output_device = output_device
        self._sequence = 0
        self._input_stream: Any = None
        self._output_stream: Any = None
        self._speaker_queue: queue.Queue[bytes] = queue.Queue(maxsize=3)
        self._lock = threading.RLock()
        self._owner: str | None = None
        self._lease_deadline = 0.0

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            instance_id="default",
            contract=AUDIO_CONTRACT,
            display_name="Microphone and speaker",
            streams=[
                StreamManifest(
                    name="microphone",
                    direction="output",
                    media_type="audio/pcm",
                    profiles=["pcm_s16le;rate=16000;channels=1;frame_ms=20"],
                ),
                StreamManifest(
                    name="speaker",
                    direction="input",
                    media_type="audio/pcm",
                    profiles=["pcm_s16le;rate=16000;channels=1;frame_ms=20"],
                ),
            ],
            actions=[
                ActionManifest(
                    name="session_status",
                    description="Return the current exclusive audio-session status.",
                    permission="read",
                    input_schema={"type": "object", "additionalProperties": False},
                    output_schema={"type": "object"},
                )
            ],
        )

    def acquire(self, controller_id: str, lease_seconds: float = 6.0) -> bool:
        now = time.monotonic()
        with self._lock:
            if self._owner not in (None, controller_id) and self._lease_deadline > now:
                return False
            self._owner = controller_id
            self._lease_deadline = now + lease_seconds
            return True

    def release(self, controller_id: str) -> None:
        with self._lock:
            if self._owner == controller_id:
                self._owner = None
                self._lease_deadline = 0.0

    def session_status(self) -> dict[str, Any]:
        with self._lock:
            active = self._owner is not None and self._lease_deadline > time.monotonic()
            return {"active": active, "owner": self._owner if active else None}

    def start_microphone(self, on_frame: Callable[[AudioFrame], None]) -> None:
        import sounddevice as sd

        def callback(data: np.ndarray, _frames: int, _time: Any, status: Any) -> None:
            if status:
                return
            self._sequence += 1
            pcm = np.clip(data[:, 0], -1.0, 1.0)
            payload = (pcm * 32767).astype("<i2", copy=False).tobytes()
            on_frame(AudioFrame(self._sequence, time.time_ns(), payload))

        self._input_stream = sd.InputStream(
            device=self.input_device,
            samplerate=self.sample_rate,
            channels=self.channels,
            blocksize=self.block_size,
            dtype="float32",
            callback=callback,
        )
        self._input_stream.start()

    def start_speaker(self) -> None:
        import sounddevice as sd

        self._output_stream = sd.RawOutputStream(
            device=self.output_device,
            samplerate=self.sample_rate,
            channels=self.channels,
            blocksize=self.block_size,
            dtype="int16",
        )
        self._output_stream.start()

    def play(self, frame: AudioFrame) -> None:
        if self._output_stream is None:
            self.start_speaker()
        try:
            self._speaker_queue.put_nowait(frame.payload)
        except queue.Full:
            self._speaker_queue.get_nowait()
            self._speaker_queue.put_nowait(frame.payload)
        self._output_stream.write(self._speaker_queue.get_nowait())

    def stop(self) -> None:
        for stream in (self._input_stream, self._output_stream):
            if stream is not None:
                stream.stop()
                stream.close()
        self._input_stream = None
        self._output_stream = None

    @staticmethod
    def devices() -> list[dict[str, Any]]:
        import sounddevice as sd

        return [dict(device) for device in sd.query_devices()]
