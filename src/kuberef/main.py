"""Main module for kuberef - Kubernetes Secret reference validator."""

import sys
import json
import typer
from pathlib import Path
from typing import Optional
from typing_extensions import Annotated 
from rich.console import Console

from kuberef.watcher import YamlAuditHandler

console = Console()
app = typer.Typer()


def emit_ndjson(event_name: str, payload: dict) -> None:
    """Helper to stream strict, single-line Newline-Delimited JSON (NDJSON)."""
    stream_packet = {"event": event_name}
    stream_packet.update(payload)
    # separators=(',', ':') strips out whitespace to ensure strict single-line compliance
    json_string = json.dumps(stream_packet, separators=(',', ':'))
    sys.stdout.write(json_string + '\n')
    sys.stdout.flush()


def audit_kubernetes_manifests(path: Path, watch_and_json: bool = False) -> None:
    """Audit Kubernetes manifests in the given path."""
    if not watch_and_json:
        console.print(f"[bold blue]Auditing Kubernetes manifests in: {path}[/bold blue]")
    
    # Placeholder for audit evaluation results payload
    audit_results = {"status": "success", "errors": []} 
    
    if watch_and_json:
        emit_ndjson("audit_summary", {"results": audit_results, "path": str(path)})
    else:
        console.print("[green]Audit complete![/green]")


@app.command()
def start(
    path: Annotated[
        Optional[str],
        typer.Option(
            "--path",
            "-p",
            help="Path to Kubernetes manifests directory to audit",
        ),
    ] = ".",
    watch: Annotated[
        bool,
        typer.Option(
            "--watch",
            "-w",
            help="Watch for changes and re-audit automatically",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output evaluation summary as JSON machine-readable format",
        ),
    ] = False,
) -> None:
    """Start the kuberef validator."""
    manifest_path = Path(path).resolve()

    if not manifest_path.exists():
        if watch and json_output:
            emit_ndjson("error", {"message": f"Path does not exist: {manifest_path}"})
        else:
            console.print(f"[red]Error: Path does not exist: {manifest_path}[/red]")
        raise typer.Exit(1)

    watch_and_json = watch and json_output

    if watch_and_json:
        emit_ndjson("watcher_started", {"path": str(manifest_path), "status": "active"})
    
    # Run the initial pass
    audit_kubernetes_manifests(manifest_path, watch_and_json=watch_and_json)

    if watch:
        if not watch_and_json:
            console.print("[yellow]Watching for changes... (Press Ctrl+C to exit)[/yellow]")
        
        def watch_callback(p):
            if watch_and_json:
                emit_ndjson("change_detected", {"file": str(p)})
            else:
                console.print(f"⟳ Change detected in: {p}")
            audit_kubernetes_manifests(manifest_path, watch_and_json=watch_and_json)

        handler = YamlAuditHandler(audit_callback=watch_callback)
        
        if not watch_and_json:
            console.print("[green]Watch mode not yet fully implemented[/green]")


if __name__ == "__main__":
    app()