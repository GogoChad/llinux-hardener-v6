import socket
from .models import AuditReport, CheckResult
from .policy import load_policy, selected_controls
from .registry import available_ids, run_control
from .plugins.manager import load_plugins
from .utils import detect_os


def calculate_score(results):
    weights = {"critical": 12, "high": 8, "medium": 4, "low": 2, "info": 1}
    total = sum(weights.get(r.severity, 4) for r in results if r.status not in {"SKIP", "ERROR"})
    lost = sum(weights.get(r.severity, 4) for r in results if r.status == "FAIL")
    if total == 0:
        return 100
    return max(0, round((1 - lost / total) * 100))


def audit(policy_path: str | None = None, include_plugins: bool = False) -> AuditReport:
    policy = load_policy(policy_path)
    ids = selected_controls(policy, available_ids())
    results = []
    for control_id in ids:
        try:
            results.append(run_control(control_id))
        except Exception as exc:
            results.append(CheckResult(control_id, "Control error", "engine", "high", "ERROR", str(exc), tags=["error"]))
    if include_plugins:
        for control_id, func in load_plugins("hardener/plugins").items():
            try:
                results.append(func())
            except Exception as exc:
                results.append(CheckResult(control_id, "Plugin error", "plugin", "medium", "ERROR", str(exc), tags=["plugin", "error"]))
    os_name, os_version = detect_os()
    return AuditReport(socket.gethostname(), os_name, os_version, calculate_score(results), results)
