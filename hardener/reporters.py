import json
from pathlib import Path
from .models import AuditReport


def as_json(report: AuditReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def save_json(report: AuditReport, path: str):
    Path(path).write_text(as_json(report), encoding="utf-8")


def save_html(report: AuditReport, path: str):
    rows = []
    for r in report.results:
        rows.append(f"<tr><td>{r.control_id}</td><td>{r.status}</td><td>{r.severity}</td><td>{r.title}</td><td>{r.message}</td></tr>")
    html = f"""<!doctype html><html><head><meta charset='utf-8'><title>Linux Hardener</title>
    <style>body{{font-family:Arial;margin:2rem}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:.5rem;text-align:left}}.score{{font-size:2rem}}</style>
    </head><body><h1>Linux Hardener</h1><div class='score'>Score: {report.score}/100</div><p>{report.hostname} — {report.os_name} {report.os_version}</p>
    <table><tr><th>ID</th><th>Status</th><th>Severity</th><th>Title</th><th>Message</th></tr>{''.join(rows)}</table></body></html>"""
    Path(path).write_text(html, encoding="utf-8")


def save_sarif(report: AuditReport, path: str):
    results = []
    for r in report.results:
        if r.status == "PASS":
            continue
        results.append({
            "ruleId": r.control_id,
            "level": "error" if r.severity in {"critical", "high"} else "warning",
            "message": {"text": r.message},
        })
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "linux-hardener"}}, "results": results}]}
    Path(path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
