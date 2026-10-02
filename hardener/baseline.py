import json
from pathlib import Path
from .models import AuditReport


def save_baseline(report: AuditReport, path: str):
    baseline = {r.control_id: r.status for r in report.results}
    Path(path).write_text(json.dumps({"hostname": report.hostname, "score": report.score, "statuses": baseline}, indent=2), encoding="utf-8")


def compare_baseline(report: AuditReport, path: str) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    expected = data.get("statuses", {})
    drift = []
    for r in report.results:
        old = expected.get(r.control_id)
        if old and old != r.status:
            drift.append({"control_id": r.control_id, "before": old, "now": r.status})
    return drift
