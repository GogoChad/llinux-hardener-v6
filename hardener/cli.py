import argparse
import json
import sys

from .engine import audit
from .policy import load_policy
from .registry import available_ids
from .baseline import save_baseline, compare_baseline
from .remediation import remediate, rollback, list_runs
from .reporters import save_json, save_html, save_sarif
from .utils import command_output, detect_os, is_root


def print_report(report):
    print(f"\nLinux Hardener v0.6 - {report.hostname}")
    print(f"OS: {report.os_name} {report.os_version}")
    print(f"Score: {report.score}/100\n")
    print(f"{'ID':<14} {'STATUS':<7} {'SEVERITY':<9} MESSAGE")
    print("-" * 86)
    for r in report.results:
        print(f"{r.control_id:<14} {r.status:<7} {r.severity:<9} {r.message}")
    counts = {s: sum(1 for r in report.results if r.status == s) for s in ["PASS", "FAIL", "WARN", "SKIP", "ERROR"]}
    print(f"\nPASS={counts['PASS']} FAIL={counts['FAIL']} WARN={counts['WARN']} SKIP={counts['SKIP']} ERROR={counts['ERROR']}")


def cmd_doctor():
    os_name, os_version = detect_os()
    print("Linux Hardener doctor")
    print(f"OS: {os_name} {os_version}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Root: {'yes' if is_root() else 'no'}")
    for binary in ["ss", "systemctl", "sysctl", "sshd", "nft", "ufw", "docker"]:
        found = bool(command_output(["bash", "-lc", f"command -v {binary}"]))
        print(f"{binary:<10}: {'found' if found else 'not found'}")


def main():
    parser = argparse.ArgumentParser(description="Linux hardening and compliance toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    p_audit = sub.add_parser("audit")
    p_audit.add_argument("--policy")
    p_audit.add_argument("--json")
    p_audit.add_argument("--html")
    p_audit.add_argument("--sarif")
    p_audit.add_argument("--plugins", action="store_true")
    p_audit.add_argument("--fail-on", choices=["low", "medium", "high", "critical"])

    p_rem = sub.add_parser("remediate")
    p_rem.add_argument("--only", nargs="*")
    p_rem.add_argument("--dry-run", action="store_true")

    p_base = sub.add_parser("baseline")
    p_base.add_argument("--output", default="baseline.json")
    p_drift = sub.add_parser("drift")
    p_drift.add_argument("baseline")

    p_rb = sub.add_parser("rollback")
    p_rb.add_argument("run_id")
    sub.add_parser("list-runs")
    sub.add_parser("list-controls")
    sub.add_parser("doctor")
    sub.add_parser("version")

    args = parser.parse_args()

    if args.command == "version":
        print("0.6.0")
        return
    if args.command == "doctor":
        cmd_doctor()
        return
    if args.command == "list-controls":
        for cid in available_ids():
            print(cid)
        return
    if args.command == "list-runs":
        for run in list_runs():
            print(run)
        return
    if args.command == "rollback":
        if not is_root():
            raise SystemExit("Rollback requires root. Use sudo.")
        rollback(args.run_id)
        print(f"Rollback complete: {args.run_id}")
        return

    if args.command == "audit":
        report = audit(args.policy, include_plugins=args.plugins)
        print_report(report)
        if args.json:
            save_json(report, args.json)
        if args.html:
            save_html(report, args.html)
        if args.sarif:
            save_sarif(report, args.sarif)
        if args.fail_on:
            order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            threshold = order[args.fail_on]
            bad = any(r.status == "FAIL" and order.get(r.severity, 0) >= threshold for r in report.results)
            if bad:
                raise SystemExit(2)
        return

    if args.command == "baseline":
        report = audit()
        save_baseline(report, args.output)
        print(f"Baseline saved to {args.output}")
        return

    if args.command == "drift":
        report = audit()
        drift = compare_baseline(report, args.baseline)
        if not drift:
            print("No drift detected.")
            return
        print(json.dumps(drift, indent=2))
        raise SystemExit(2)

    if args.command == "remediate":
        run_id, changes = remediate(args.only, dry_run=args.dry_run)
        print(f"Run: {run_id}")
        for change in changes:
            print(f"  {change}")
        print("DRY RUN: no real change was applied." if args.dry_run else "Changes applied and validated where supported.")
        return


if __name__ == "__main__":
    main()
