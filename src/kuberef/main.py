import typer
import yaml
from kubernetes import client, config
from rich.console import Console
from rich.table import Table
from pathlib import Path

app = typer.Typer()
console = Console()

def get_required_secrets(file_path: str):
    """Safely extracts secret names from YAML."""
    try:
        with open(file_path, 'r') as f:
            data = yaml.safe_load(f)
        
        if not isinstance(data, dict):
            return []

        found = []
        template_spec = data.get('spec', {}).get('template', {}).get('spec', {})
        containers = template_spec.get('containers', [])
        
        for c in containers:
            for env in c.get('env', []):
                name = env.get('valueFrom', {}).get('secretKeyRef', {}).get('name')
                if name:
                    found.append(name)
        return list(set(found))
    except Exception:
        return []

@app.command()
def check(
    file_path: str, 
    namespace: str = typer.Option("default", "--namespace", "-n", help="The K8s namespace to check")
):
    """Audit a YAML file against a specific namespace."""
    if not Path(file_path).exists():
        console.print(f"[red]Error: File {file_path} not found![/red]")
        return

    required = get_required_secrets(file_path)
    
    try:
        config.load_kube_config()
        v1 = client.CoreV1Api()
        live_data = v1.list_namespaced_secret(namespace)
        live_names = [s.metadata.name for s in live_data.items]
        
        table = Table(title=f"Kuberef Audit: {file_path}", title_style="bold blue")
        table.add_column("Secret Name", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Namespace", style="magenta")

        if not required:
            console.print("[yellow]No secrets found to validate.[/yellow]")
            return

        for secret in required:
            status = "✅ [green]FOUND[/green]" if secret in live_names else "❌ [red]MISSING[/red]"
            table.add_row(secret, status, namespace)
        
        console.print(table)
        # --------------------------------
                
    except Exception as e:
        console.print(f"[bold red]K8s Error:[/bold red] {e}")

def start():
    app()

if __name__ == "__main__":
    start()
