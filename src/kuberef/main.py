import json
import typer
import yaml
from pathlib import Path
from typing import List, Dict, Any, Set
from rich.console import Console
from rich.table import Table
from kubernetes import client, config
from kubernetes.client.rest import ApiException

app = typer.Typer()
console = Console()


def find_pod_specs(data: Any) -> List[Dict[str, Any]]:
    """
    ANALYSIS NOTE: Recursively searches through dictionaries/lists to extract
    Kubernetes Pod Spec layouts (Handles Deployments, Jobs, StatefulSets, etc.).
    If any format parser acts faulty here, check if the input manifest is valid K8s syntax.
    """
    specs = []
    if isinstance(data, dict):
        if "containers" in data and isinstance(data["containers"], list):
            specs.append(data)
        for value in data.values():
            specs.extend(find_pod_specs(value))
    elif isinstance(data, list):
        for item in data:
            specs.extend(find_pod_specs(item))
    return specs


def get_secret_refs(data: Dict[str, Any]) -> Dict[str, Set[str]]:
    """
    ANALYSIS NOTE: Maps secret names to the keys they are supposed to provide.
    If secrets or keys are extracted incorrectly, analyze how environment values
    (env, envFrom, volumes, imagePullSecrets) are structured in the source document.
    """
    all_refs = {}

    def add_ref(name: str, key: str = None):
        if not name:
            return
        if name not in all_refs:
            all_refs[name] = set()
        if key:
            all_refs[name].add(key)

    for spec in find_pod_specs(data):
        containers = spec.get("containers", []) + spec.get("initContainers", [])
        for c in containers:
            for env in c.get("env", []):
                if "valueFrom" in env and "secretKeyRef" in env["valueFrom"]:
                    ref = env["valueFrom"]["secretKeyRef"]
                    add_ref(ref.get("name"), ref.get("key"))
            for ef in c.get("envFrom", []):
                if "secretRef" in ef:
                    add_ref(ef["secretRef"].get("name"))

        for vol in spec.get("volumes", []):
            if "secret" in vol:
                add_ref(vol.get("secret", {}).get("secretName"))

        for ps in spec.get("imagePullSecrets", []):
            add_ref(ps.get("name"))

    return all_refs


def build_summary(files_scanned: int, passed: int, failed: int, warnings: int, files: list):
    """Generates the standardized summary dictionary object for the final audit reporting."""
    return {
        "files_scanned": files_scanned,
        "passes": passed,
        "failures": failed,
        "warnings": warnings,
        "files": files,
    }


def run_audit(files_to_scan: List[Path], namespace: str, v1: Any, quiet: bool = False, json_output: bool = False) -> int:
    """
    ANALYSIS NOTE: Core audit sequence logic. Matches local references against active live cluster configs.
    BUG FIX FOR NDJSON: Removed 'indent=2' formatting when printing summary JSON so that
    it streams out as a clean, single line compatible with continuous NDJSON watching pipelines.
    """
    global_passed, global_failed, global_warnings = 0, 0, 0
    json_results = []

    for yaml_file in files_to_scan:
        with open(yaml_file, "r") as f:
            try:
                docs = yaml.safe_load_all(f)
                combined_refs: Dict[str, Set[str]] = {}
                for doc in docs:
                    if not doc:
                        continue
                    for name, keys in get_secret_refs(doc).items():
                        combined_refs.setdefault(name, set()).update(keys)
            except yaml.YAMLError:
                if json_output:
                   json_results.append({
                       "file": yaml_file.name,
                       "status": "INVALID_YAML"
                   })
                else:
                    console.print(
                       f"[bold red]Error:[/bold red] Invalid YAML format in {yaml_file.name}. Skipping..."
                    )
                continue
        if not combined_refs:
            continue
        file_results = []

        table = Table(title=f"Security Audit: {yaml_file.name}")
        table.add_column("Secret Name", style="cyan")
        table.add_column("Status", justify="left")

        for name, keys in combined_refs.items():
            try:
                secret = v1.read_namespaced_secret(name, namespace)
                if keys:
                    existing_keys = (secret.data or {}).keys()
                    missing = [k for k in keys if k not in existing_keys]
                    if missing:
                        table.add_row(
                            name,
                            f"[bold yellow]KEY MISSING: {', '.join(missing)}[/bold yellow]",
                        )
                        file_results.append({
                                "secret": name,
                                "status": "WARNING",
                                "missing_keys": missing
                        })
                        global_warnings += 1
                    else:
                        table.add_row(name, "[bold green]PASS[/bold green]")
                        file_results.append({
                             "secret": name,
                             "status": "PASS"
                        })
                        global_passed += 1
                else:
                    table.add_row(name, "[bold green]PASS (Found)[/bold green]")
                    file_results.append({
                        "secret": name,
                        "status": "PASS"
                    })
                    global_passed += 1
            except ApiException as e:
                if e.status == 404:
                    table.add_row(name, "[bold red]FAIL (Secret Missing)[/bold red]")
                    file_results.append({
                            "secret": name,
                            "status": "FAIL"
                    })
                    global_failed += 1
                else:
                    table.add_row(name, f"[dim]Error {e.status}[/dim]")
                    global_failed += 1

        json_results.append({
            "file": yaml_file.name,
            "results": file_results
        })

        if not quiet and not json_output:
            console.print(table)

    summary = build_summary(len(files_to_scan), global_passed, global_failed, global_warnings, json_results)
    if json_output:
        # CHANGED: Dropped indent=2 to maintain valid NDJSON output stream formatting
        print(json.dumps(summary))        
    else:
        console.print("\n" + "━" * 30)
        console.print("[bold underline]AUDIT SUMMARY[/bold underline]\n")
        console.print(f"📂 Files Scanned: {len(files_to_scan)}")
        console.print(f"✅ Total Passed:   [green]{global_passed}[/green]")
        console.print(f"❌ Total Failed:   [red]{global_failed}[/red]")
        console.print(f"⚠️  Total Warnings: [yellow]{global_warnings}[/yellow]")
        console.print("━" * 30 + "\n")

    return 1 if (global_failed > 0 or global_warnings > 0) else 0


EXCLUDE_DIRS = {
    ".git", ".github", ".venv", "venv", "node_modules", 
    "__pycache__", "build", "dist", ".tox", ".mypy_cache", ".pytest_cache"
}


def get_yaml_files(target_path: Path) -> List[Path]:
    """Recursively gets all YAML files, filtering out standard excluded directories."""
    files = list(target_path.rglob("*.yaml")) + list(target_path.rglob("*.yml"))
    return [
        f for f in files
        if not any(part in EXCLUDE_DIRS for part in f.relative_to(target_path).parts)
    ]


@app.command()
def audit(
    path_str: str = typer.Argument(..., help="Path to K8s YAML file or directory"),
    namespace: str = typer.Option("default", "--namespace", "-n"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Silence per-file status tables and print only the summary"),
    watch: bool = typer.Option(False, "--watch", "-w", help="Stay running and re-audit on every .yaml/.yml file change."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output summary in JSON format"),
):
    """Deep audit entry point command wrapper."""
    target_path = Path(path_str)

    files_to_scan: List[Path] = []
    if target_path.is_dir():
        files_to_scan = get_yaml_files(target_path)
    elif target_path.is_file():
        files_to_scan = [target_path]
    else:
        console.print(f"[bold red]Error:[/bold red] Path {path_str} not found!")
        raise typer.Exit(1)

    if not files_to_scan:
        console.print(f"[yellow]No YAML files found at {path_str}[/yellow]")
        return

    try:
        config.load_kube_config()
        _, active_context = config.list_kube_config_contexts()
        cluster_name = active_context["name"]
        v1 = client.CoreV1Api()
        v1.read_namespace(name=namespace)
        if not json_output:
           console.print(f"[bold blue]Target Cluster:[/bold blue] {cluster_name}")
    except Exception as e:
        console.print(f"[bold red]Pre-flight Error:[/bold red] {str(e)}")
        raise typer.Exit(1)

    exit_code = run_audit(files_to_scan, namespace, v1, quiet=quiet, json_output=json_output)

    if watch:
        from kuberef.watcher import run_watch_mode

        def _on_change(changed_path: Path) -> None:
            if target_path.is_dir():
                updated_files = get_yaml_files(target_path)
            else:
                updated_files = [changed_path]
            run_audit(updated_files, namespace, v1, quiet=quiet, json_output=json_output)

        # CHANGED: Passing down the json_output parameter to configure streaming in the watcher loop.
        run_watch_mode(target_path, _on_change, json_output=json_output)
    else:
        raise typer.Exit(exit_code)


def start():
    app()


if __name__ == "__main__":
    start()