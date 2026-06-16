import typer
import yaml
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple
from rich.console import Console
from rich.table import Table
from kubernetes import client, config
from kubernetes.client.rest import ApiException

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

def get_configmap_refs(data: Dict[str, Any]) -> Dict[str, Set[str]]:
    """Maps ConfigMap names to the specific keys they need to provide."""
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
            # Pattern 1: env.valueFrom.configMapKeyRef
            for env in c.get("env", []):
                if "valueFrom" in env and "configMapKeyRef" in env["valueFrom"]:
                    ref = env["valueFrom"]["configMapKeyRef"]
                    add_ref(ref.get("name"), ref.get("key"))
            
            # Pattern 2: envFrom.configMapRef
            for ef in c.get("envFrom", []):
                if "configMapRef" in ef:
                    add_ref(ef["configMapRef"].get("name"))

        # Pattern 3: volumes.configMap (not common, but possible)
        for vol in spec.get("volumes", []):
            if "configMap" in vol:
                add_ref(vol.get("configMap", {}).get("name"))

    return all_refs

@app.command()
def audit(
    path_str: str = typer.Argument(..., help="Path to K8s YAML file or directory"),
    namespace: str = typer.Option("default", "--namespace", "-n"),
    context: str = typer.Option(None, "--context", help="Kubernetes context to use"),
    kubeconfig: str = typer.Option(None, "--kubeconfig", help="Path to kubeconfig file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Silence per-file status tables and print only the summary")
):
    """Audit Kubernetes manifests for missing Secrets and ConfigMaps."""
    
    path = Path(path_str)
    if path.is_file():
        files_to_scan = [path]
    elif path.is_dir():
        files_to_scan = list(path.glob("*.yaml")) + list(path.glob("*.yml"))
    else:
        console.print(f"[bold red]Error:[/bold red] Path '{path_str}' does not exist")
        raise typer.Exit(1)

    if not files_to_scan:
        console.print(f"[bold yellow]Warning:[/bold yellow] No YAML files found in '{path_str}'")
        return

    try:
        if kubeconfig:
            config.load_kube_config(config_file=kubeconfig, context=context)
        else:
            config.load_kube_config(context=context)
        
        _, active_context = config.list_kube_config_contexts()
        cluster_name = active_context['name'] if active_context else "unknown"
        v1 = client.CoreV1Api()
        v1.read_namespace(name=namespace)
        console.print(f"[bold blue]Target Cluster:[/bold blue] {cluster_name}")
        console.print(f"[bold blue]Target Namespace:[/bold blue] {namespace}")
    except Exception as e:
        console.print(f"[bold red]Pre-flight Error:[/bold red] {str(e)}")
        raise typer.Exit(1)

    global_passed, global_failed, global_warnings = 0, 0, 0
    secret_passed, secret_failed = 0, 0
    configmap_passed, configmap_failed = 0, 0

    for yaml_file in files_to_scan:
        with open(yaml_file, "r") as f:
            try:
                docs = yaml.safe_load_all(f)
                secret_refs = {}
                configmap_refs = {}
                
                for doc in docs:
                    if not doc:
                        continue
                    for name, keys in get_secret_refs(doc).items():
                        secret_refs.setdefault(name, set()).update(keys)
                    for name, keys in get_configmap_refs(doc).items():
                        configmap_refs.setdefault(name, set()).update(keys)
                        
            except yaml.YAMLError:
                console.print(f"[bold red]Error:[/bold red] Invalid YAML format in {yaml_file.name}. Skipping...")
                continue

        if not secret_refs and not configmap_refs:
            continue

        # Secrets Table
        if secret_refs:
            secret_table = Table(title=f"🔐 Secret Audit: {yaml_file.name}", style="cyan")
            secret_table.add_column("Secret Name", style="cyan")
            secret_table.add_column("Status", justify="left")
            
            for name, keys in secret_refs.items():
                try:
                    secret = v1.read_namespaced_secret(name, namespace)
                    if keys:
                        existing_keys = (secret.data or {}).keys()
                        missing = [k for k in keys if k not in existing_keys]
                        if missing:
                            secret_table.add_row(name, f"[bold yellow]KEY MISSING: {', '.join(missing)}[/bold yellow]")
                            global_warnings += 1
                        else:
                            secret_table.add_row(name, "[bold green]PASS[/bold green]")
                            global_passed += 1
                            secret_passed += 1
                    else:
                        secret_table.add_row(name, "[bold green]PASS (Found)[/bold green]")
                        global_passed += 1
                        secret_passed += 1
                except ApiException as e:
                    if e.status == 404:
                        secret_table.add_row(name, "[bold red]FAIL (Secret Missing)[/bold red]")
                        global_failed += 1
                        secret_failed += 1
                    else:
                        secret_table.add_row(name, f"[dim]Error {e.status}[/dim]")
                        global_failed += 1
                        secret_failed += 1
            
            if not quiet:
                console.print(secret_table)

        # ConfigMaps Table
        if configmap_refs:
            cm_table = Table(title=f"📄 ConfigMap Audit: {yaml_file.name}", style="green")
            cm_table.add_column("ConfigMap Name", style="green")
            cm_table.add_column("Status", justify="left")
            
            for name, keys in configmap_refs.items():
                try:
                    configmap = v1.read_namespaced_config_map(name, namespace)
                    if keys:
                        existing_keys = (configmap.data or {}).keys()
                        missing = [k for k in keys if k not in existing_keys]
                        if missing:
                            cm_table.add_row(name, f"[bold yellow]KEY MISSING: {', '.join(missing)}[/bold yellow]")
                            global_warnings += 1
                        else:
                            cm_table.add_row(name, "[bold green]PASS[/bold green]")
                            global_passed += 1
                            configmap_passed += 1
                    else:
                        cm_table.add_row(name, "[bold green]PASS (Found)[/bold green]")
                        global_passed += 1
                        configmap_passed += 1
                except ApiException as e:
                    if e.status == 404:
                        cm_table.add_row(name, "[bold red]FAIL (ConfigMap Missing)[/bold red]")
                        global_failed += 1
                        configmap_failed += 1
                    else:
                        cm_table.add_row(name, f"[dim]Error {e.status}[/dim]")
                        global_failed += 1
                        configmap_failed += 1
            
            if not quiet:
                console.print(cm_table)

    # Summary
    console.print("\n" + "━" * 40)
    console.print("[bold underline]AUDIT SUMMARY[/bold underline]\n")
    console.print(f"📂 Files Scanned: {len(files_to_scan)}")
    console.print(f"")
    console.print(f"🔐 Secrets:")
    console.print(f"   ✅ Passed:   [green]{secret_passed}[/green]")
    console.print(f"   ❌ Failed:   [red]{secret_failed}[/red]")
    console.print(f"")
    console.print(f"📄 ConfigMaps:")
    console.print(f"   ✅ Passed:   [green]{configmap_passed}[/green]")
    console.print(f"   ❌ Failed:   [red]{configmap_failed}[/red]")
    console.print(f"")
    console.print(f"📊 Total:")
    console.print(f"   ✅ Total Passed:   [green]{global_passed}[/green]")
    console.print(f"   ❌ Total Failed:   [red]{global_failed}[/red]")
    console.print(f"   ⚠️ Total Warnings: [yellow]{global_warnings}[/yellow]")
    console.print("━" * 40 + "\n")

    if global_failed > 0 or global_warnings > 0:
        raise typer.Exit(code=1)

def start():
    app()

if __name__ == "__main__":
    start()