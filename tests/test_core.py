import os
from pathlib import Path

from hardener.engine import calculate_score
from hardener.models import AuditReport
from hardener.models import CheckResult
from hardener.policy import selected_controls
from hardener.baseline import save_baseline, compare_baseline
from hardener.reporters import save_json, save_html, save_sarif


def test_score():
    results = [
        CheckResult("A", "a", "x", "high", "PASS", "ok"),
        CheckResult("B", "b", "x", "high", "FAIL", "bad"),
    ]
    assert calculate_score(results) == 50


def test_policy_selection():
    assert selected_controls({"enabled": ["A", "C"]}, ["A", "B"]) == ["A"]
    assert selected_controls({"disabled": ["B"]}, ["A", "B"]) == ["A"]


def test_reports_and_baseline(tmp_path):
    report = AuditReport("test-host", "Test", "1", 90, [CheckResult("A", "a", "x", "high", "PASS", "ok")])
    data = tmp_path / "report.json"
    html = tmp_path / "report.html"
    sarif = tmp_path / "report.sarif"
    baseline = tmp_path / "baseline.json"
    save_json(report, str(data))
    save_html(report, str(html))
    save_sarif(report, str(sarif))
    save_baseline(report, str(baseline))
    assert data.exists() and html.exists() and sarif.exists() and baseline.exists()
    assert compare_baseline(report, str(baseline)) == []


def test_all_builtin_controls_run():
    from hardener.registry import available_ids, run_control
    results = [run_control(cid) for cid in available_ids()]
    assert len(results) >= 25
    assert all(r.control_id for r in results)


def test_cli_import():
    from hardener.cli import main
    assert callable(main)
