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