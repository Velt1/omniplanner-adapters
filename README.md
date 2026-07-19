# Omniplanner Adapters

Lightweight adapters let Linux devices expose hardware capabilities to DimOS
without installing the full robotics stack. The first contract is a low-latency
16 kHz mono microphone/speaker adapter.

```bash
uv tool install "omniplanner-adapters[audio] @ git+https://github.com/Velt1/omniplanner-adapters@v0.1.0"
dimos-adapter init --name workshop-audio
dimos-adapter audio devices
dimos-adapter pairing-code
dimos-adapter serve audio
```

Adapter state lives below `$XDG_STATE_HOME/dimos-adapter` and is written with
owner-only permissions. Same-LAN discovery uses Zenoh peer scouting. Pass
`--connect tcp/<router-ip>:7447` when a Zenoh router bridges subnets.

## Capability SDK

Plugins expose a versioned `CapabilityManifest`. Unknown actions remain
self-describing through JSON Schema, while typed streams require a capability
contract known to both endpoints. Plugins are discovered through the
`dimos_adapter.capabilities` entry-point group.
