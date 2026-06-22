from kuberef.main import get_secret_refs, get_yaml_files

def test_recursive_discovery():
    """Test that secrets are found deep inside nested structures (like a Deployment)."""
    manifest = {
        "kind": "Deployment",
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": "app",
                        "env": [{
                            "name": "DB_PASS",
                            "valueFrom": {"secretKeyRef": {"name": "db-secret", "key": "password"}}
                        }]
                    }]
                }
            }
        }
    }
    refs = get_secret_refs(manifest)
    assert "db-secret" in refs
    assert "password" in refs["db-secret"]

def test_empty_manifest():
    """Ensure the tool doesn't crash on empty or non-k8s YAML."""
    manifest = {"random": "data"}
    refs = get_secret_refs(manifest)
    assert refs == {}

def test_multi_document_parsing():
    """Ensure secrets are discovered across multiple YAML documents."""

    import yaml

    multi_doc_yaml = """
---
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        env:
        - name: DB_PASS
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password

---
kind: Pod
spec:
  containers:
  - name: worker
    env:
    - name: API_KEY
      valueFrom:
        secretKeyRef:
          name: api-secret
          key: token
"""

    docs = yaml.safe_load_all(multi_doc_yaml)

    combined_refs = {}

    for doc in docs:
        if not doc:
            continue

        for name, keys in get_secret_refs(doc).items():
            combined_refs.setdefault(name, set()).update(keys)

    assert "db-secret" in combined_refs
    assert "password" in combined_refs["db-secret"]

    assert "api-secret" in combined_refs
    assert "token" in combined_refs["api-secret"]

def test_invalid_yaml_handling():
    """Test that the audit command gracefully handles malformed YAML files without crashing."""
    import os
    from unittest.mock import patch, MagicMock
    from typer.testing import CliRunner
    from kuberef.main import app

    runner = CliRunner()
    
    with patch("kuberef.main.config.load_kube_config") as mock_load, \
         patch("kuberef.main.config.list_kube_config_contexts") as mock_contexts, \
         patch("kuberef.main.client.CoreV1Api") as mock_api_class:
        
        mock_contexts.return_value = (None, {"name": "mock-cluster"})
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        # Mock read_namespaced_secret to return correct Kubernetes secret objects
        def mock_read_secret(name, namespace=None):
            secret_data = {
                "registry-creds": {},
                "db-secret": {"password": "some-password-hash"},
                "api-keys": {},
                "ssl-certs": {},
                "controller-level-secret": {"api-token": "some-token"},
                "nested-app-secret": {"password": "some-password"}
            }
            if name in secret_data:
                secret = MagicMock()
                secret.data = secret_data[name]
                return secret
            from kubernetes.client.rest import ApiException
            raise ApiException(status=404, reason="Not Found")
            
        mock_api.read_namespaced_secret.side_effect = mock_read_secret
        
        # Resolve test-manifests to an absolute path
        test_manifests_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "test-manifests")
        )
        
        result = runner.invoke(app, [test_manifests_dir])
        
        # The tool should finish with exit code 0 or 1, and not crash with an exception.
        assert result.exit_code in (0, 1)
        # It should contain a clear error/warning message about malformed-pod.yaml.
        assert "Invalid YAML" in result.output
        assert "malformed-pod.yaml" in result.output


def test_quiet_mode():
    """Test that the audit command suppresses per-file tables when the quiet option is enabled."""
    import os
    from unittest.mock import patch, MagicMock
    from typer.testing import CliRunner
    from kuberef.main import app

    runner = CliRunner()
    
    with patch("kuberef.main.config.load_kube_config") as mock_load, \
         patch("kuberef.main.config.list_kube_config_contexts") as mock_contexts, \
         patch("kuberef.main.client.CoreV1Api") as mock_api_class:
        
        mock_contexts.return_value = (None, {"name": "mock-cluster"})
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        # Mock read_namespaced_secret
        def mock_read_secret(name, namespace=None):
            secret = MagicMock()
            secret.data = {}
            return secret
            
        mock_api.read_namespaced_secret.side_effect = mock_read_secret
        
        test_manifests_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "test-manifests")
        )
        
        # Test short option -q
        result_q = runner.invoke(app, [test_manifests_dir, "-q"])
        assert result_q.exit_code in (0, 1)
        assert "Security Audit:" not in result_q.output
        assert "AUDIT SUMMARY" in result_q.output
        
        # Test long option --quiet
        result_quiet = runner.invoke(app, [test_manifests_dir, "--quiet"])
        assert result_quiet.exit_code in (0, 1)
        assert "Security Audit:" not in result_quiet.output
        assert "AUDIT SUMMARY" in result_quiet.output


import os
import yaml
from kuberef.main import get_secret_refs  # Compiles the parser method

def test_complex_pod_secret_references():
    """
    Verifies that the parser extracts all 4 core Secret reference patterns
    (env, envFrom, volumes, and imagePullSecrets) from a real manifest file.
    """
    # 1. Safely locate the test-manifests directory relative to this file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    manifest_path = os.path.join(project_root, "test-manifests", "complex-pod.yaml")
    
    # 2. Read and parse the raw static YAML file from disk
    with open(manifest_path, "r") as file:
        manifest_data = yaml.safe_load(file)
        
    # 3. Pass the parsed dictionary data to the Kuberef discovery engine
    discovered_secrets = get_secret_refs(manifest_data)
    
    # 4. Assert that all 4 expected target secrets are extracted properly
    assert "registry-creds" in discovered_secrets, "Failed to extract secret from imagePullSecrets"
    assert "db-secret" in discovered_secrets, "Failed to extract secret from env.valueFrom"
    assert "api-keys" in discovered_secrets, "Failed to extract secret from envFrom"
    assert "ssl-certs" in discovered_secrets, "Failed to extract secret from volumes"


def test_get_yaml_files_excludes_directories(tmp_path):
    """Verify that get_yaml_files discovers valid YAMLs and filters out build/env/meta directories."""
    # Create valid manifest files
    valid_dir = tmp_path / "manifests"
    valid_dir.mkdir()
    valid_file = valid_dir / "pod.yaml"
    valid_file.write_text("kind: Pod")
    
    # Create files inside excluded directories
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    git_file = git_dir / "config.yaml"
    git_file.write_text("some-git-config")
    
    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()
    venv_file = venv_dir / "lib.yml"
    venv_file.write_text("some-venv-config")
    
    node_modules_dir = tmp_path / "node_modules"
    node_modules_dir.mkdir()
    node_modules_file = node_modules_dir / "package.yaml"
    node_modules_file.write_text("npm-yaml")
    
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    build_file = build_dir / "build-config.yaml"
    build_file.write_text("some-build-config")
    
    # Run the get_yaml_files helper
    discovered = get_yaml_files(tmp_path)
    
    # Assertions: Only pod.yaml should be found
    discovered_names = [f.name for f in discovered]
    assert "pod.yaml" in discovered_names
    assert "config.yaml" not in discovered_names
    assert "lib.yml" not in discovered_names
    assert "package.yaml" not in discovered_names
    assert "build-config.yaml" not in discovered_names
    assert len(discovered) == 1


def test_get_yaml_files_with_excluded_name_in_parent_path(tmp_path):
    """Verify that get_yaml_files does not exclude files just because a parent directory contains an excluded name."""
    # Create a parent directory named 'venv'
    parent_dir = tmp_path / "venv"
    parent_dir.mkdir()
    
    # Create a target directory inside the 'venv' folder
    target_dir = parent_dir / "my-project"
    target_dir.mkdir()
    
    # Create a valid yaml manifest inside 'my-project'
    valid_file = target_dir / "deployment.yaml"
    valid_file.write_text("kind: Deployment")
    
    # Scan the target directory
    discovered = get_yaml_files(target_dir)
    
    # It should discover the valid deployment.yaml file!
    discovered_names = [f.name for f in discovered]
    assert "deployment.yaml" in discovered_names
    assert len(discovered) == 1