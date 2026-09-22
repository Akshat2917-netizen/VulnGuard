"""End-to-end checks for the dashboard upload and scan transport."""

import io
import zipfile

from fastapi.testclient import TestClient

from vulnguard.models.risk_scorer import RiskResult
from vulnguard.ui.server import create_app


class _FakeGraph:
    seen_state = None

    async def astream(self, state):
        type(self).seen_state = state
        yield {
            "red_agent": {
                "vulnerability_found": True,
                "exploit_harness": "print('EXPLOIT_SUCCESS')",
                "pipeline_status": "RED_COMPLETE",
            }
        }
        yield {
            "blue_agent": {
                "patched_code": "def unsafe(value):\n    return value",
                "patch_diff": "- return eval(value)\n+ return value",
                "pipeline_status": "BLUE_COMPLETE",
            }
        }
        yield {
            "judge_agent": {
                "judge_verdict": "PASS",
                "pipeline_status": "COMPLETE",
            }
        }


def test_upload_and_scan_workflow(monkeypatch, tmp_path):
    monkeypatch.setattr("vulnguard.models.risk_scorer.RiskScorer.__init__", lambda self: None)
    monkeypatch.setattr(
        "vulnguard.models.risk_scorer.RiskScorer.optimal_threshold",
        property(lambda self: 65),
    )
    monkeypatch.setattr(
        "vulnguard.models.risk_scorer.RiskScorer.score",
        lambda self, code, language: RiskResult(risk_score=100.0),
    )
    monkeypatch.setattr("vulnguard.agents.graph.compile_graph", lambda: _FakeGraph())

    app = create_app(
        db_path=tmp_path / "scans.db",
        upload_root=tmp_path / "uploads",
    )
    with TestClient(app) as client:
        response = client.post(
            "/upload",
            files={
                "file": (
                    "sample.py",
                    b"import os\r\n\r\ndef unsafe(value):\r\n    return eval(value)\r\n",
                    "text/x-python",
                )
            },
        )
        assert response.status_code == 200
        function = response.json()["functions"][0]
        assert function["name"] == "unsafe"

        with client.websocket_connect("/ws/scan") as websocket:
            websocket.send_json(function)
            events = []
            while True:
                event = websocket.receive_json()
                events.append(event)
                if event["type"] in {"complete", "error"}:
                    break

        scan_id = events[-1]["scan_id"]
        result = client.get(f"/api/results/{scan_id}")
        metrics = client.get("/api/metrics")

    assert events[-1]["type"] == "complete"
    assert [event.get("agent") for event in events if event.get("agent")] == [
        "red_agent", "blue_agent", "judge_agent"
    ]
    assert _FakeGraph.seen_state["context_bundle"]["imports"] == ["import os"]
    assert result.status_code == 200
    assert result.json()["patch_diff"].startswith("- return")
    assert metrics.json()["patches_validated"] == 1


def test_zip_repository_upload(tmp_path):
    archive_data = io.BytesIO()
    with zipfile.ZipFile(archive_data, "w") as archive:
        archive.writestr("sample/main.py", "from helper import clean\n\ndef run(value):\n    return clean(value)\n")
        archive.writestr("sample/helper.py", "def clean(value):\n    return value\n")

    app = create_app(db_path=tmp_path / "scans.db", upload_root=tmp_path / "uploads")
    with TestClient(app) as client:
        response = client.post(
            "/upload",
            files={"file": ("sample.zip", archive_data.getvalue(), "application/zip")},
        )

    assert response.status_code == 200
    assert response.json()["repository"] is True
    assert response.json()["files_scanned"] == 2
    assert {item["name"] for item in response.json()["functions"]} == {"run", "clean"}


def test_zip_path_traversal_is_rejected(tmp_path):
    archive_data = io.BytesIO()
    with zipfile.ZipFile(archive_data, "w") as archive:
        archive.writestr("../escape.py", "print('nope')")

    app = create_app(db_path=tmp_path / "scans.db", upload_root=tmp_path / "uploads")
    with TestClient(app) as client:
        response = client.post(
            "/upload",
            files={"file": ("unsafe.zip", archive_data.getvalue(), "application/zip")},
        )

    assert response.status_code == 400
    assert "unsafe path" in response.json()["detail"]
