import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from kubernetes.client.rest import ApiException
from kuberef.main import app

def test_watch_mode_does_not_exit_on_failure():
    """Verify that --watch mode starts run_watch_mode and doesn't exit, even with failing audits."""
    runner = CliRunner()
    
    with patch("kuberef.main.config.load_kube_config") as mock_load, \
         patch("kuberef.main.config.list_kube_config_contexts") as mock_contexts, \
         patch("kuberef.main.client.CoreV1Api") as mock_api_class, \
         patch("kuberef.watcher.run_watch_mode") as mock_run_watch:
        
        mock_contexts.return_value = (None, {"name": "mock-cluster"})
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        # Simulate all secret lookups failing (404 Not Found), meaning audit fails
        def mock_read_secret(name, namespace=None):
            raise ApiException(status=404, reason="Not Found")
            
        mock_api.read_namespaced_secret.side_effect = mock_read_secret
        
        # Locate complex-pod.yaml (which has secrets and will fail audit)
        current_dir = os.path.dirname(os.path.abspath(__file__))
        test_manifest = os.path.join(current_dir, "..", "test-manifests", "complex-pod.yaml")
        
        # 1. Run WITHOUT --watch: should exit with code 1
        result_no_watch = runner.invoke(app, [test_manifest])
        assert result_no_watch.exit_code == 1
        mock_run_watch.assert_not_called()
        
        # 2. Run WITH --watch: should NOT exit on failure, should start watch mode
        # Reset mock
        mock_run_watch.reset_mock()
        result_watch = runner.invoke(app, [test_manifest, "--watch"])
        
        # It should exit with code 0 (since CliRunner finishes invocation without unhandled Exit)
        # and run_watch_mode should have been called
        assert result_watch.exit_code == 0
        mock_run_watch.assert_called_once()
        
        # Extract the callback passed to run_watch_mode
        call_args = mock_run_watch.call_args
        watch_path = call_args[0][0]
        on_change_callback = call_args[0][1]
        
        assert watch_path == Path(test_manifest)
        assert callable(on_change_callback)
        
        on_change_callback(Path(test_manifest))
