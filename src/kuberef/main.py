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
    TEXT = "text"
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
        if not name: return
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

@app.command()
def audit(
    path_str: str = typer.Argument(..., help="Path to K8s YAML file or directory"),
    namespace: str = typer.Option("default", "--namespace", "-n"),
    format: OutputFormat = typer.Option(OutputFormat.TEXT, "--format", help="Output format (text, github, sarif)")
):
    """
Deep audit: Checks files or directories against Cluster, Namespace,
and Secret keys.

Examples:
  kuberef deployment.yaml  # Scan a single manifest file
  kuberef ./k8s-manifests/ # Scan an entire directory
 
"""
    
    
    target_path = Path(path_str)

    files_to_scan = []
    if target_path.is_dir():

        files_to_scan = list(target_path.rglob("*.yaml")) + list(target_path.rglob("*.yml"))       
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
        cluster_name = active_context['name']
        v1 = client.CoreV1Api()
        v1.read_namespace(name=namespace)
        console.print(f"[bold blue]Target Cluster:[/bold blue] {cluster_name}")
    except Exception as e:
        console.print(f"[bold red]Pre-flight Error:[/bold red] {str(e)}")
        raise typer.Exit(1)

    global_passed, global_failed, global_warnings = 0, 0, 0
    sarif_results = []

    for yaml_file in files_to_scan:
        with open(yaml_file, "r") as f:
            try:
                docs = yaml.safe_load_all(f)
                combined_refs = {}
                for doc in docs:
                    if not doc: continue
                    for name, keys in get_secret_refs(doc).items():
                        combined_refs.setdefault(name, set()).update(keys)
            except yaml.YAMLError:
                console.print(f"[bold red]Error:[/bold red] Invalid YAML format in {yaml_file.name}. Skipping...")
                continue

        if not combined_refs:
            continue

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
                        table.add_row(name, f"[bold yellow]KEY MISSING: {', '.join(missing)}[/bold yellow]")
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
                        global_passed += 1
                else:
                    table.add_row(name, "[bold green]PASS (Found)[/bold green]")
                    global_passed += 1
            except ApiException as e:
                file_path = yaml_file.as_posix()
                if e.status == 404:
                    table.add_row(name, "[bold red]FAIL (Secret Missing)[/bold red]")
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
        
        console.print(table)

    console.print("\n" + "━" * 30)
    console.print("[bold underline]AUDIT SUMMARY[/bold underline]\n")
    console.print(f"📂 Files Scanned: {len(files_to_scan)}")
    console.print(f"✅ Total Passed:   [green]{global_passed}[/green]")
    console.print(f"❌ Total Failed:   [red]{global_failed}[/red]")
    console.print(f"⚠️ Total Warnings: [yellow]{global_warnings}[/yellow]")
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

    if global_failed > 0 or global_warnings > 0:
        raise typer.Exit(code=1)

def start():
    app()

if __name__ == "__main__":
    start()