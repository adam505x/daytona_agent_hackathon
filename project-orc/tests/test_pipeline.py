"""
Basic smoke tests — run with: pytest tests/
These mock Daytona so you can test logic without spending credits.
"""
import json
import os
import sys
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ── extractor ──────────────────────────────────────────────────────────────

def test_extract_tasks_parses_json(tmp_path):
    doc = tmp_path / "doc.txt"
    doc.write_text("AI is transforming healthcare and finance sectors.")

    fake_tasks = [
        {"id": 1, "topic": "AI in healthcare", "context": "...", "priority": "high"},
        {"id": 2, "topic": "AI in finance", "context": "...", "priority": "medium"},
    ]

    mock_msg = MagicMock()
    mock_msg.content = [MagicMock(text=json.dumps(fake_tasks))]

    with patch("orchestrator.extractor.anthropic.Anthropic") as MockClient:
        MockClient.return_value.messages.create.return_value = mock_msg
        from orchestrator.extractor import extract_tasks
        tasks = extract_tasks(str(doc))

    assert len(tasks) == 2
    assert tasks[0]["topic"] == "AI in healthcare"


# ── dispatcher ─────────────────────────────────────────────────────────────

def test_dispatch_collects_results():
    tasks = [
        {"id": 1, "topic": "topic A", "context": "ctx A", "priority": "high"},
        {"id": 2, "topic": "topic B", "context": "ctx B", "priority": "low"},
    ]

    fake_result = json.dumps({"task_id": 1, "topic": "topic A",
                               "status": "ok", "findings": "some findings"})

    mock_process = MagicMock()
    mock_process.code_run.return_value = MagicMock(exit_code=0, result=fake_result)

    mock_sandbox = MagicMock()
    mock_sandbox.id = "sandbox-test-001"
    mock_sandbox.process = mock_process

    mock_daytona = MagicMock()
    mock_daytona.create.return_value = mock_sandbox

    with patch("orchestrator.dispatcher.Daytona", return_value=mock_daytona), \
         patch("orchestrator.dispatcher.DaytonaConfig"), \
         patch("builtins.open", MagicMock(return_value=MagicMock(
             __enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value="code"))),
             __exit__=MagicMock(return_value=False)))):
        from orchestrator.dispatcher import dispatch
        results = dispatch(tasks)

    assert len(results) == 2


# ── utils ──────────────────────────────────────────────────────────────────

def test_chunk_list():
    from shared.utils import chunk_list
    assert chunk_list([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]


def test_save_output(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from shared.utils import save_output
    path = save_output({"key": "value"}, "test.json")
    assert os.path.exists(path)
    with open(path) as f:
        data = json.load(f)
    assert data["key"] == "value"
