from kuberef.main import get_configmap_refs

def test_configmap_discovery():
    """Test that ConfigMaps are correctly extracted from Pod specs."""
    manifest = {
        "kind": "Pod",
        "spec": {
            "containers": [{
                "name": "app",
                "env": [{
                    "name": "MY_ENV",
                    "valueFrom": {"configMapKeyRef": {"name": "my-config", "key": "some-key"}}
                }],
                "envFrom": [{"configMapRef": {"name": "default-config"}}]
            }]
        }
    }
    
    refs = get_configmap_refs(manifest)
    
    assert "my-config" in refs
    assert "some-key" in refs["my-config"]
    assert "default-config" in refs
    print("\n✅ ConfigMap Extraction Engine is working perfectly!")