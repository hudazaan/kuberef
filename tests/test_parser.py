import pytest
import yaml
from unittest.mock import patch, MagicMock
from kuberef.main import get_secret_refs, preprocess_manifest, preprocess_manifests, audit
from typer.testing import CliRunner
from kubernetes.client.rest import ApiException
from kuberef.main import app

def test_preprocess_manifest_preserves_metadata():
    """Test that preprocess_manifest preserves kind/name and extracts pod_specs for a Rollout-style doc."""
    doc = {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "Rollout",
        "metadata": {
            "name": "sample-rollout"
        },
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
    p_doc = preprocess_manifest(doc)
    assert p_doc is not None
    assert p_doc["kind"] == "Rollout"
    assert p_doc["name"] == "sample-rollout"
    assert len(p_doc["pod_specs"]) == 1
    assert p_doc["pod_specs"][0]["containers"][0]["name"] == "app"

def test_get_secret_refs_new_signature():
    """Test that get_secret_refs(pod_specs) works on the new signature."""
    pod_specs = [
        {
            "containers": [{
                "name": "app",
                "env": [{
                    "name": "DB_PASS",
                    "valueFrom": {"secretKeyRef": {"name": "db-secret", "key": "password"}}
                }]
            }]
        }
    ]
    refs = get_secret_refs(pod_specs)
    assert "db-secret" in refs
    assert "password" in refs["db-secret"]

def test_empty_manifest():
    """Ensure the tool doesn't crash on empty or non-k8s YAML."""
    manifest = {"random": "data"}
    p_doc = preprocess_manifest(manifest)
    assert p_doc is not None
    refs = get_secret_refs(p_doc.get("pod_specs", []))
    assert refs == {}

def test_combined_refs_deduplication():
    """Test combined_refs deduplication across multiple docs in one file."""
    multi_doc_yaml = """
---
kind: Deployment
metadata:
  name: deploy1
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
metadata:
  name: pod1
spec:
  containers:
  - name: worker
    env:
    - name: API_KEY
      valueFrom:
        secretKeyRef:
          name: db-secret
          key: token
"""
    docs = list(yaml.safe_load_all(multi_doc_yaml))
    processed_docs = preprocess_manifests(docs)
    
    combined_refs = {}
    for p_doc in processed_docs:
        refs = get_secret_refs(p_doc["pod_specs"])
        for name, keys in refs.items():
            combined_refs.setdefault(name, set()).update(keys)

    assert "db-secret" in combined_refs
    assert "password" in combined_refs["db-secret"]
    assert "token" in combined_refs["db-secret"]
    assert len(combined_refs) == 1

@patch("kuberef.main.client.CoreV1Api")
@patch("kuberef.main.config.load_kube_config")
@patch("kuberef.main.config.list_kube_config_contexts")
def test_audit_with_mock_client(mock_list_contexts, mock_load_config, mock_core_v1_api, tmp_path):
    """Test the audit function with a mocked kubernetes client."""
    mock_list_contexts.return_value = (None, {"name": "Test-Cluster"})
    mock_v1 = MagicMock()
    mock_core_v1_api.return_value = mock_v1
    
    # Setup mock secret response
    mock_secret = MagicMock()
    mock_secret.data = {"password": "base64data"}
    mock_v1.read_namespaced_secret.return_value = mock_secret
    
    # Create a temporary manifest file
    manifest_path = tmp_path / "test-manifest.yaml"
    manifest_path.write_text("""
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: test-container
    env:
    - name: TEST_ENV
      valueFrom:
        secretKeyRef:
          name: db-secret
          key: password
""")

    runner = CliRunner()
    result = runner.invoke(app, [str(manifest_path)])
    
    # It should succeed because the secret and key exist in the mock
    assert result.exit_code == 0
    mock_v1.read_namespaced_secret.assert_called_once_with("db-secret", "default")