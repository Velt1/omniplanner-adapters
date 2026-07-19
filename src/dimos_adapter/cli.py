"""Command-line interface for lightweight adapter devices."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import typer

from dimos_adapter.audio import AudioCapability
from dimos_adapter.runtime import AdapterRuntime
from dimos_adapter.state import AdapterState

app = typer.Typer(no_args_is_help=True)
audio_app = typer.Typer(no_args_is_help=True)
service_app = typer.Typer(no_args_is_help=True)
app.add_typer(audio_app, name="audio")
app.add_typer(service_app, name="service")


@app.command("init")
def initialize(
    name: str = typer.Option(..., help="Human-readable adapter name."),
    state_dir: Path | None = typer.Option(None),
) -> None:
    state = AdapterState(state_dir)
    identity = state.initialize(name)
    typer.echo(f"Initialized {name} ({identity.device_id}) in {state.root}")


@app.command("pairing-code")
def pairing_code(state_dir: Path | None = typer.Option(None)) -> None:
    token = AdapterState(state_dir).create_token()
    typer.echo(token.value)
    typer.echo("Single use; expires in 10 minutes.", err=True)


@audio_app.command("devices")
def audio_devices() -> None:
    typer.echo(json.dumps(AudioCapability.devices(), indent=2))


@app.command("serve")
def serve(
    capability: str = typer.Argument("audio"),
    connect: list[str] = typer.Option([], help="Zenoh router endpoint."),
    input_device: int | None = typer.Option(None),
    output_device: int | None = typer.Option(None),
    state_dir: Path | None = typer.Option(None),
) -> None:
    if capability != "audio":
        raise typer.BadParameter("v0.1 supports only the audio capability")
    state = AdapterState(state_dir)
    if not state.identity_path.exists():
        raise typer.BadParameter("run `dimos-adapter init --name ...` first")
    runtime = AdapterRuntime(
        state,
        [AudioCapability(input_device=input_device, output_device=output_device)],
        connect,
    )
    try:
        runtime.run_forever()
    except KeyboardInterrupt:
        runtime.stop()


@service_app.command("install")
def service_install(
    state_dir: Path | None = typer.Option(None),
    connect: list[str] = typer.Option([]),
) -> None:
    state = AdapterState(state_dir)
    if not state.identity_path.exists():
        raise typer.BadParameter("run `dimos-adapter init --name ...` first")
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    args = ["dimos-adapter", "serve", "audio"]
    for endpoint in connect:
        args.extend(["--connect", endpoint])
    unit = unit_dir / "dimos-adapter.service"
    unit.write_text(
        "\n".join(
            [
                "[Unit]",
                "Description=DimOS device adapter",
                "After=network-online.target sound.target",
                "",
                "[Service]",
                f"ExecStart={' '.join(args)}",
                "Restart=on-failure",
                "RestartSec=2",
                "",
                "[Install]",
                "WantedBy=default.target",
                "",
            ]
        )
    )
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "--user", "enable", "--now", unit.name], check=True)
    typer.echo(f"Installed {unit}")
