import json
import typer
import yaml
import json
from pathlib import Path
from typing import List, Dict, Any, Set
from enum import Enum
from rich.console import Console
from rich.table import Table
from kubernetes import client, config
from kubernetes.client.rest import ApiException

class OutputFormat(str, Enum):
    TABLE = "table"
    GITHUB = "github"
    SARIF = "sarif"

app = typer.Typer()
console = Console()


def find_pod_specs(data: Any) -> List[Dict[str, Any]]:
    """Recursively finds all Pod 'spec' blocks (handles Deployments, Jobs, etc.)."""
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
    """Maps secret names to the specific keys they need to provide."""
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
    return {
        "files_scanned": files_scanned,
        "passes": passed,
        "failures": failed,
        "warnings": warnings,
        "files": files,
    }


def run_audit(
    files_to_scan: List[Path],
    namespace: str,
    v1: Any,
    format: OutputFormat = OutputFormat.TABLE,
    quiet: bool = False,
    json_output: bool = False,
) -> int:
    """
    Core audit logic. Scans the given files against the live cluster.
    Returns exit code: 0 for clean, 1 for failures/warnings.
    """
    global_passed, global_failed, global_warnings = 0, 0, 0
    sarif_results = []
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
                    global_failed += 1
                else:
                    console.print(
                        f"[bold red]Error:[/bold red] Invalid YAML format in {yaml_file.name}. Skipping..."
                    )
                    global_failed += 1
                    file_path = yaml_file.as_posix()
                    if format == OutputFormat.GITHUB:
                        print(
                            f"::error file={file_path},title=Invalid YAML::Invalid YAML format in {yaml_file.name}."
                        )
                    elif format == OutputFormat.SARIF:
                        sarif_results.append({
                            "ruleId": "KR000",
                            "level": "error",
                            "message": {
                                "text": f"Invalid YAML format in {yaml_file.name}."
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": file_path
                                        }
                                    }
                                }
                            ]
                        })
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
                        file_path = yaml_file.as_posix()
                        for k in missing:
                            if format == OutputFormat.GITHUB:
                                print(f"::warning file={file_path},title=Missing Secret Key::The key '{k}' in secret '{name}' was not found.")
                            sarif_results.append({
                                "ruleId": "KR002",
                                "level": "warning",
                                "message": {
                                    "text": f"The key '{k}' in secret '{name}' was not found."
                                },
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": file_path
                                            }
                                        }
                                    }
                                ]
                            })
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
                file_path = yaml_file.as_posix()
                if e.status == 404:
                    table.add_row(name, "[bold red]FAIL (Secret Missing)[/bold red]")
                    file_results.append({
                            "secret": name,
                            "status": "FAIL"
                    })
                    global_failed += 1
                    if format == OutputFormat.GITHUB:
                        print(f"::error file={file_path},title=Missing Secret Reference::The secret '{name}' was not found in the cluster.")
                    sarif_results.append({
                        "ruleId": "KR001",
                        "level": "error",
                        "message": {
                            "text": f"The secret '{name}' was not found in the cluster."
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": file_path
                                    }
                                }
                            }
                        ]
                    })
                else:
                    table.add_row(name, f"[dim]Error {e.status}[/dim]")
                    global_failed += 1
                    if format == OutputFormat.GITHUB:
                        print(f"::error file={file_path},title=Kubernetes API Error::Received HTTP {e.status} when checking secret '{name}'.")
                    sarif_results.append({
                        "ruleId": "KR003",
                        "level": "error",
                        "message": {
                            "text": f"Received HTTP {e.status} when checking secret '{name}'."
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": file_path
                                    }
                                }
                            }
                        ]
                    })
        
        json_results.append({
            "file": yaml_file.name,
            "results": file_results
        })

        if not quiet and not json_output:
            console.print(table)

    summary = build_summary(len(files_to_scan), global_passed, global_failed, global_warnings, json_results)
    if json_output:
        print(json.dumps(summary, indent=2))        
    else:
        console.print("\n" + "━" * 30)
        console.print("[bold underline]AUDIT SUMMARY[/bold underline]\n")
        console.print(f"📂 Files Scanned: {len(files_to_scan)}")
        console.print(f"✅ Total Passed:   [green]{global_passed}[/green]")
        console.print(f"❌ Total Failed:   [red]{global_failed}[/red]")
        console.print(f"⚠️  Total Warnings: [yellow]{global_warnings}[/yellow]")
        console.print("━" * 30 + "\n")

    if format == OutputFormat.SARIF:
        sarif_data = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "kuberef",
                            "rules": [
                                {
                                    "id": "KR000",
                                    "name": "InvalidYaml",
                                    "shortDescription": {
                                        "text": "Invalid YAML file format"
                                    }
                                },
                                {
                                    "id": "KR001",
                                    "name": "MissingSecret",
                                    "shortDescription": {
                                        "text": "Kubernetes Secret Reference missing in cluster"
                                    }
                                },
                                {
                                    "id": "KR002",
                                    "name": "MissingSecretKey",
                                    "shortDescription": {
                                        "text": "Kubernetes Secret Key missing in cluster"
                                    }
                                },
                                {
                                    "id": "KR003",
                                    "name": "KubernetesApiError",
                                    "shortDescription": {
                                        "text": "Kubernetes API returned an unexpected error code"
                                    }
                                }
                            ]
                        }
                    },
                    "results": sarif_results
                }
            ]
        }
        with open("results.sarif", "w") as sarif_file:
            json.dump(sarif_data, sarif_file, indent=2)
        console.print("[bold green]SARIF report exported to results.sarif[/bold green]")

    return 1 if (global_failed > 0 or global_warnings > 0) else 0


EXCLUDE_DIRS = {
    ".git",
    ".github",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "build",
    "dist",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
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
    format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="Output format (table, github, sarif)"
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Silence per-file status tables and print only the summary",
    ),
    watch: bool = typer.Option(
        False,
        "--watch",
        "-w",
        help="Stay running and re-audit on every .yaml/.yml file change.",
    ),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output summary in JSON format"),
):
    """
Deep audit: Checks files or directories against Cluster, Namespace,
and Secret keys.

Examples:
  kuberef deployment.yaml             # Scan a single manifest file
  kuberef ./k8s-manifests/            # Scan an entire directory
  kuberef deployment.yaml --watch     # Re-audit automatically on file changes
  kuberef ./k8s-manifests/ -w         # Watch an entire directory

"""
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

    exit_code = run_audit(files_to_scan, namespace, v1, format=format, quiet=quiet, json_output=json_output)

    if watch:
        from kuberef.watcher import run_watch_mode

        def _on_change(changed_path: Path) -> None:
            if target_path.is_dir():
                updated_files = get_yaml_files(target_path)
            else:
                updated_files = [changed_path]
            try:
                run_audit(
                    updated_files,
                    namespace,
                    v1,
                    format=format,
                    quiet=quiet,
                    json_output=json_output,
                )
            except Exception as e:
                console.print(f"[bold red]Error during re-audit:[/bold red] {str(e)}")

        run_watch_mode(target_path, _on_change)
    else:
        raise typer.Exit(exit_code)


def start():
    app()


if __name__ == "__main__":
    start()
