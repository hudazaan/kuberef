"""Unit tests for the watch mode handler (no live cluster or real filesystem needed)."""

from pathlib import Path
from unittest.mock import MagicMock, patch, call

from watchdog.events import FileModifiedEvent, FileCreatedEvent, DirModifiedEvent

from kuberef.watcher import YamlAuditHandler, run_watch_mode


# ---------------------------------------------------------------------------
# YamlAuditHandler tests
# ---------------------------------------------------------------------------

def _make_handler():
    callback = MagicMock()
    handler = YamlAuditHandler(audit_callback=callback)
    return handler, callback


def test_handler_triggers_on_yaml_modified():
    """Modifying a .yaml file must invoke the audit callback."""
    handler, callback = _make_handler()
    event = FileModifiedEvent("/some/path/deployment.yaml")
    handler.on_modified(event)
    callback.assert_called_once_with(Path("/some/path/deployment.yaml"))


def test_handler_triggers_on_yml_modified():
    """Modifying a .yml file must invoke the audit callback."""
    handler, callback = _make_handler()
    event = FileModifiedEvent("/some/path/service.yml")
    handler.on_modified(event)
    callback.assert_called_once_with(Path("/some/path/service.yml"))


def test_handler_triggers_on_yaml_created():
    """Creating a new .yaml file must invoke the audit callback."""
    handler, callback = _make_handler()
    event = FileCreatedEvent("/some/path/new-manifest.yaml")
    handler.on_created(event)
    callback.assert_called_once_with(Path("/some/path/new-manifest.yaml"))


@patch("kuberef.watcher.time.time")
def test_handler_suppresses_rapid_events(mock_time):
    """Multiple rapid events for the same file should trigger the callback only once."""
    handler, callback = _make_handler()
    
    # Event 1 at T=0
    mock_time.return_value = 0.0
    event1 = FileModifiedEvent("/some/path/deployment.yaml")
    handler.on_modified(event1)
    
    # Event 2 at T=0.1 (within default 0.5s cooldown)
    mock_time.return_value = 0.1
    event2 = FileModifiedEvent("/some/path/deployment.yaml")
    handler.on_modified(event2)
    
    # Callback should be called exactly once
    callback.assert_called_once_with(Path("/some/path/deployment.yaml"))


@patch("kuberef.watcher.time.time")
def test_handler_recovers_after_cooldown(mock_time):
    """Event after the cooldown window should trigger the callback again."""
    handler, callback = _make_handler()
    
    # Event 1 at T=0
    mock_time.return_value = 0.0
    handler.on_modified(FileModifiedEvent("/some/path/deployment.yaml"))
    
    # Event 2 at T=0.6 (after 0.5s cooldown)
    mock_time.return_value = 0.6
    handler.on_modified(FileModifiedEvent("/some/path/deployment.yaml"))
    
    # Callback should be called twice
    assert callback.call_count == 2


@patch("kuberef.watcher.time.time")
def test_handler_independent_files(mock_time):
    """Rapid events on different files should trigger separate callbacks."""
    handler, callback = _make_handler()
    
    # Both events at T=0 (simultaneous save of two files)
    mock_time.return_value = 0.0
    handler.on_modified(FileModifiedEvent("/some/path/file_a.yaml"))
    handler.on_modified(FileModifiedEvent("/some/path/file_b.yaml"))
    
    # Callback should be called once for each file
    assert callback.call_count == 2
    callback.assert_any_call(Path("/some/path/file_a.yaml"))
    callback.assert_any_call(Path("/some/path/file_b.yaml"))


def test_handler_ignores_non_yaml_files():
    """Non-.yaml/.yml file changes must NOT trigger the callback."""
    handler, callback = _make_handler()
    event = FileModifiedEvent("/some/path/readme.txt")
    handler.on_modified(event)
    callback.assert_not_called()


def test_handler_ignores_directory_events():
    """Directory-level events must NOT trigger the callback."""
    handler, callback = _make_handler()
    event = DirModifiedEvent("/some/path/")
    handler.on_modified(event)
    callback.assert_not_called()


def test_handler_ignores_json_files():
    """JSON files must NOT trigger the callback."""
    handler, callback = _make_handler()
    event = FileModifiedEvent("/some/path/config.json")
    handler.on_modified(event)
    callback.assert_not_called()


# ---------------------------------------------------------------------------
# run_watch_mode tests
# ---------------------------------------------------------------------------

def test_run_watch_mode_starts_and_stops_cleanly(tmp_path):
    """
    run_watch_mode should start an Observer, then exit cleanly on KeyboardInterrupt.
    No real filesystem watching is performed — Observer is fully mocked.
    """
    callback = MagicMock()

    with patch("kuberef.watcher.Observer") as MockObserver:
        mock_observer = MagicMock()
        MockObserver.return_value = mock_observer

        # Simulate Ctrl+C after the first sleep tick
        with patch("kuberef.watcher.time.sleep", side_effect=KeyboardInterrupt):
            run_watch_mode(tmp_path, callback)

        mock_observer.start.assert_called_once()
        mock_observer.stop.assert_called_once()
        mock_observer.join.assert_called_once()


def test_run_watch_mode_watches_parent_dir_for_single_file(tmp_path):
    """
    When given a single file path, the Observer should watch its parent directory,
    not just the file (watchdog watches directories, not individual files).
    """
    yaml_file = tmp_path / "deployment.yaml"
    yaml_file.write_text("kind: Deployment\n")
    callback = MagicMock()

    with patch("kuberef.watcher.Observer") as MockObserver:
        mock_observer = MagicMock()
        MockObserver.return_value = mock_observer

        with patch("kuberef.watcher.time.sleep", side_effect=KeyboardInterrupt):
            run_watch_mode(yaml_file, callback)

        # Should schedule the parent directory, not the file itself
        scheduled_path = mock_observer.schedule.call_args[0][1]
        assert scheduled_path == str(tmp_path)


def test_run_watch_mode_watches_directory_directly(tmp_path):
    """When given a directory, the Observer should watch that directory."""
    callback = MagicMock()

    with patch("kuberef.watcher.Observer") as MockObserver:
        mock_observer = MagicMock()
        MockObserver.return_value = mock_observer

        with patch("kuberef.watcher.time.sleep", side_effect=KeyboardInterrupt):
            run_watch_mode(tmp_path, callback)

        scheduled_path = mock_observer.schedule.call_args[0][1]
        assert scheduled_path == str(tmp_path)
