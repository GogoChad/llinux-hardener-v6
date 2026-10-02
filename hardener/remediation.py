from pathlib import Path
from datetime import datetime
import json
import os
import shutil
import tempfile

from .engine import audit
from .utils import is_root, command_ok, read_text

RUN_ROOT = Path("/var/lib/linux-hardener/runs")

SSH_FIXES = {
    "SSH-001": ("PermitRootLogin", "no"),
    "SSH-002": ("PermitEmptyPasswords", "no"),
    "SSH-003": ("PasswordAuthentication", "no"),
    "SSH-004": ("X11Forwarding", "no"),
    "SSH-005": ("MaxAuthTries", "4"),
    "SSH-006": ("AllowTcpForwarding", "no"),
}
SYSCTL_FIXES = {
    "KERNEL-001": ("net.ipv4.ip_forward", "0"),
    "KERNEL-002": ("net.ipv4.conf.all.accept_redirects", "0"),
    "KERNEL-003": ("net.ipv4.conf.all.send_redirects", "0"),
    "KERNEL-004": ("net.ipv4.conf.all.rp_filter", "1"),
    "KERNEL-005": ("net.ipv4.conf.all.accept_source_route", "0"),
    "KERNEL-006": ("net.ipv4.tcp_syncookies", "1"),
    "KERNEL-007": ("net.ipv6.conf.all.accept_redirects", "0"),
}


def make_run_dir() -> Path:
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = RUN_ROOT / run_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_change(run_dir: Path, path: str, old_exists: bool, old_text: str | None) -> None:
    safe = path.strip("/").replace("/", "_") + ".backup"
    meta = {"path": path, "old_exists": old_exists, "backup": safe}
    (run_dir / "manifest.jsonl").open("a", encoding="utf-8").write(json.dumps(meta) + "\n")
    if old_exists and old_text is not None:
        (run_dir / safe).write_text(old_text, encoding="utf-8")


def update_key_value(path: str, key: str, value: str, run_dir: Path, dry_run: bool) -> str:
    target = Path(path)
    old_exists = target.exists()
    old_text = read_text(path) if old_exists else ""
    lines = old_text.splitlines()
    replaced = False
    output = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and stripped.split()[0].lower() == key.lower():
            output.append(f"{key} {value}")
            replaced = True
        else:
            output.append(line)
    if not replaced:
        output.append(f"{key} {value}")
    new_text = "\n".join(output).rstrip() + "\n"
    if not dry_run:
        write_change(run_dir, path, old_exists, old_text)
        target.write_text(new_text, encoding="utf-8")
    return "modified"


def write_sysctl(key: str, value: str, run_dir: Path, dry_run: bool) -> str:
    path = "/etc/sysctl.d/99-linux-hardener.conf"
    old_exists = Path(path).exists()
    old_text = read_text(path) if old_exists else ""
    if f"{key} " in old_text:
        lines = [f"{key} = {value}" if l.strip().startswith(key) else l for l in old_text.splitlines()]
        new_text = "\n".join(lines) + "\n"
    else:
        new_text = old_text.rstrip() + ("\n" if old_text.strip() else "") + f"{key} = {value}\n"
    if not dry_run:
        write_change(run_dir, path, old_exists, old_text)
        Path(path).write_text(new_text, encoding="utf-8")
        command_ok(["sysctl", "--system"], timeout=15)
    return "modified"


def remediate(only: list[str] | None = None, dry_run: bool = True) -> tuple[str, list[str]]:
    if not dry_run and not is_root():
        raise PermissionError("Real remediation requires root. Use sudo.")
    before = audit()
    selected = only or [r.control_id for r in before.results if r.status == "FAIL" and r.fixable]
    run_dir = make_run_dir() if not dry_run else Path(tempfile.mkdtemp(prefix="hardener-dryrun-"))
    changes = []
    ssh_path = "/etc/ssh/sshd_config"
    for control_id in selected:
        if control_id in SSH_FIXES:
            key, value = SSH_FIXES[control_id]
            update_key_value(ssh_path, key, value, run_dir, dry_run)
            changes.append(f"{ssh_path}: {key} -> {value}")
        elif control_id in SYSCTL_FIXES:
            key, value = SYSCTL_FIXES[control_id]
            write_sysctl(key, value, run_dir, dry_run)
            changes.append(f"sysctl: {key} -> {value}")
    if not dry_run and any(cid in SSH_FIXES for cid in selected):
        if not command_ok(["sshd", "-t"]):
            rollback(run_dir.name)
            raise RuntimeError("sshd -t failed; changes were rolled back")
        command_ok(["systemctl", "reload", "ssh"], timeout=10)
        command_ok(["systemctl", "reload", "sshd"], timeout=10)
    return run_dir.name, changes


def rollback(run_id: str) -> None:
    run_dir = RUN_ROOT / run_id
    manifest = run_dir / "manifest.jsonl"
    if not manifest.exists():
        raise FileNotFoundError(f"Run not found: {run_id}")
    for line in reversed(manifest.read_text(encoding="utf-8").splitlines()):
        meta = json.loads(line)
        path = Path(meta["path"])
        backup = run_dir / meta["backup"]
        if meta["old_exists"] and backup.exists():
            shutil.copy2(backup, path)
        elif path.exists():
            path.unlink()


def list_runs() -> list[str]:
    if not RUN_ROOT.exists():
        return []
    return sorted([p.name for p in RUN_ROOT.iterdir() if p.is_dir()])
