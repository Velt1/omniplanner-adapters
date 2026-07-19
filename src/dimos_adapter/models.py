"""Versioned wire models shared by adapters and controllers."""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

PROTOCOL_VERSION = "1.0"
AUDIO_CONTRACT = "dimos.audio.duplex/v1"
DISCOVERY_INTERVAL_SECONDS = 2.0
DISCOVERY_LEASE_SECONDS = 6.0


class StreamManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    direction: Literal["input", "output"]
    media_type: str
    profiles: list[str] = Field(default_factory=list)


class ActionManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    permission: Literal["read", "write", "admin"] = "write"
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)


class CapabilityManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instance_id: str
    contract: str
    display_name: str
    streams: list[StreamManifest] = Field(default_factory=list)
    actions: list[ActionManifest] = Field(default_factory=list)


class DeviceManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol_version: str = PROTOCOL_VERSION
    device_id: str
    display_name: str
    adapter_version: str
    boot_id: str
    lease_seconds: float = DISCOVERY_LEASE_SECONDS
    sequence: int = 0
    timestamp_ns: int = Field(default_factory=time.time_ns)
    signing_public_key: str
    exchange_public_key: str
    paired_controllers: int = 0
    capabilities: list[CapabilityManifest] = Field(default_factory=list)


class SignedManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: DeviceManifest
    signature: str


@dataclass(frozen=True, slots=True)
class AudioFrame:
    """Transport-neutral PCM frame used by the v1 audio bridge."""

    sequence: int
    timestamp_ns: int
    payload: bytes
    sample_rate: int = 16_000
    channels: int = 1
    sample_format: str = "pcm_s16le"

    _HEADER = struct.Struct(">QQIHHB")

    def __post_init__(self) -> None:
        if self.sample_rate <= 0:
            raise ValueError("sample_rate must be positive")
        if self.channels <= 0:
            raise ValueError("channels must be positive")
        if self.sample_format != "pcm_s16le":
            raise ValueError("v1 requires pcm_s16le")

    def to_bytes(self) -> bytes:
        format_bytes = self.sample_format.encode("ascii")
        if len(format_bytes) > 255:
            raise ValueError("sample format is too long")
        return (
            self._HEADER.pack(
                self.sequence,
                self.timestamp_ns,
                len(self.payload),
                self.sample_rate,
                self.channels,
                len(format_bytes),
            )
            + format_bytes
            + self.payload
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> AudioFrame:
        if len(data) < cls._HEADER.size:
            raise ValueError("truncated audio frame")
        sequence, timestamp_ns, payload_size, sample_rate, channels, format_size = (
            cls._HEADER.unpack_from(data)
        )
        body = data[cls._HEADER.size :]
        if len(body) != format_size + payload_size:
            raise ValueError("audio frame length mismatch")
        sample_format = body[:format_size].decode("ascii")
        return cls(
            sequence=sequence,
            timestamp_ns=timestamp_ns,
            payload=body[format_size:],
            sample_rate=sample_rate,
            channels=channels,
            sample_format=sample_format,
        )
