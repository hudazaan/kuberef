from kuberef.main import get_secret_refs

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

def test_github_annotations():
    """Verify that --format github prints standard GitHub workflow annotations."""
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
        
        # We mock one secret exists but misses the expected key 'password'
        # and one secret is missing entirely
        def mock_read_secret(name, namespace=None):
            if name == "db-secret":
                secret = MagicMock()
                secret.data = {} # missing key 'password'
                return secret
            from kubernetes.client.rest import ApiException
            raise ApiException(status=404, reason="Not Found")
            
        mock_api.read_namespaced_secret.side_effect = mock_read_secret
        
        # Test a specific yaml file e.g. complex-pod.yaml
        test_manifest = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "test-manifests", "complex-pod.yaml")
        )
        
        result = runner.invoke(app, [test_manifest, "--format", "github"])
        
        # It should exit with code 1
        assert result.exit_code == 1
        
        # It should print GitHub workflow annotations
        # Note: complex-pod.yaml contains references like db-secret (key: password) and api-keys
        # Let's check stdout contains standard ::error and ::warning syntax
        assert "::error" in result.output
        assert "::warning" in result.output


def test_sarif_output():
    """Verify that --format sarif generates a valid results.sarif file."""
    import os
    import json
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
        
        def mock_read_secret(name, namespace=None):
            if name == "db-secret":
                secret = MagicMock()
                secret.data = {} # missing key 'password'
                return secret
            from kubernetes.client.rest import ApiException
            raise ApiException(status=404, reason="Not Found")
            
        mock_api.read_namespaced_secret.side_effect = mock_read_secret
        
        test_manifest = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "test-manifests", "complex-pod.yaml")
        )
        
        # Clean up any pre-existing results.sarif
        if os.path.exists("results.sarif"):
            os.remove("results.sarif")
            
        try:
            result = runner.invoke(app, [test_manifest, "--format", "sarif"])
            
            assert result.exit_code == 1
            assert os.path.exists("results.sarif")
            
            with open("results.sarif", "r") as f:
                sarif_data = json.load(f)
                
            assert sarif_data["version"] == "2.1.0"
            assert len(sarif_data["runs"]) == 1
            assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "kuberef"
            
            results = sarif_data["runs"][0]["results"]
            assert len(results) > 0
            
            # Check for specific ruleIds
            rule_ids = [r["ruleId"] for r in results]
            assert "KR001" in rule_ids # MissingSecret
            assert "KR002" in rule_ids # MissingSecretKey
        finally:
            if os.path.exists("results.sarif"):
                os.remove("results.sarif")

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
