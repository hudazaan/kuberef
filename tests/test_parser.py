from kuberef.main import get_required_secrets
import pathlib

def test_extract_secrets_valid_yaml(tmp_path):
    d = tmp_path / "test.yaml"
    content = """
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: web
        env:
        - valueFrom:
            secretKeyRef:
              name: my-secret
    """
    d.write_text(content)
    
    results = get_required_secrets(str(d))
    assert "my-secret" in results

def test_extract_secrets_empty_file(tmp_path):
    d = tmp_path / "empty.yaml"
    d.write_text("")
    
    results = get_required_secrets(str(d))
    assert results == []

def test_extract_secrets_invalid_yaml(tmp_path):
    d = tmp_path / "broken.txt"
    d.write_text("this is not yaml : [")
    
    results = get_required_secrets(str(d))
    assert results == []