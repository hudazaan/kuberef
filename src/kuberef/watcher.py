import time
import argparse
from pathlib import Path
from typing import Callable
from rich.console import Console
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from kuberef.validator import my_cool_audit_function
from kuberef.formatters import stream_ndjson_event

console = Console()
YAML_SUFFIXES = {".yaml", ".yml"}

class YamlAuditHandler(FileSystemEventHandler):
    """Triggers a re-audit whenever a .yaml/.yml file is modified or created."""

    def __init__(self, audit_callback: Callable[[Path], None], json_mode: bool = False, cooldown_seconds: float = 1.5):
        super().__init__()
        self.audit_callback = audit_callback
        self.json_mode = json_mode
        self.cooldown_seconds = cooldown_seconds
        self.last_executed = {}

    def _is_yaml(self, path: str) -> bool:
        return Path(path).suffix.lower() in YAML_SUFFIXES

    def _handle_event(self, event_path: str, event_type: str):
        if not self._is_yaml(event_path):
            return
            
        current_time = time.time()
        last_time = self.last_executed.get(event_path, -float('inf'))
        
        if current_time - last_time >= self.cooldown_seconds:
            self.last_executed[event_path] = current_time
            
            # Stream as NDJSON
            stream_ndjson_event({
                "timestamp": current_time,
                "event_type": event_type,
                "file_path": event_path
            })
            
            # Console logs suppressed if json_mode is True
            if not self.json_mode:
                if event_type == "modified":
                    console.print(f"\n[bold blue]⟳ Change detected:[/bold blue] {event_path}")
                elif event_type == "created":
                    console.print(f"\n[bold blue]⟳ New file detected:[/bold blue] {event_path}")
            
            self.audit_callback(Path(event_path))

    def on_modified(self, event):
        if not event.is_directory:
            self._handle_event(event.src_path, "modified")

    def on_created(self, event):
        if not event.is_directory:
            self._handle_event(event.src_path, "created")

def run_watch_mode(watch_path: Path, audit_callback: Callable[[Path], None], json_mode: bool = False) -> None:
    """Starts the filesystem watcher and blocks until Ctrl+C."""
    watch_dir = watch_path if watch_path.is_dir() else watch_path.parent
    handler = YamlAuditHandler(audit_callback, json_mode=json_mode)
    observer = Observer()
    observer.schedule(handler, str(watch_dir), recursive=True)
    observer.start()

    if not json_mode:
        console.print(f"\n[bold green]Watch mode active.[/bold green] Monitoring: [cyan]{watch_dir}[/cyan]")
        console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        if not json_mode:
            console.print("\n[bold yellow]Watch mode stopped.[/bold yellow]")

    observer.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kuberef Watcher")
    parser.add_argument("--json", action="store_true", help="Enable NDJSON streaming mode")
    args = parser.parse_args()

    def dummy_audit(path: Path):
        my_cool_audit_function(path)

    run_watch_mode(Path("."), dummy_audit, json_mode=args.json)