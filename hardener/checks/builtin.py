from pathlib import Path
import os
import pwd
import grp
import stat

from ..models import CheckResult
from ..utils import command_output, read_text, sysctl_value, parse_key_values


def result(cid, title, category, severity, status, message, evidence=None, fixable=False, tags=None):
    return CheckResult(cid, title, category, severity, status, message, evidence, fixable, tags or [])


def ssh_config() -> dict[str, str]:
    path = Path("/etc/ssh/sshd_config")
    if not path.exists():
        return {}
    data = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            data[parts[0].lower()] = parts[1].strip()
    return data


def check_ssh_root():
    cfg = ssh_config()
    value = cfg.get("permitrootlogin", "yes").lower()
    status = "PASS" if value in {"no", "prohibit-password", "forced-commands-only"} else "FAIL"
    return result("SSH-001", "Disable direct SSH root login", "ssh", "high", status,
                  f"PermitRootLogin = {value}", cfg.get("permitrootlogin"), True, ["ssh", "authentication"])


def check_empty_passwords():
    cfg = ssh_config()
    value = cfg.get("permitemptypasswords", "no").lower()
    return result("SSH-002", "Disable empty SSH passwords", "ssh", "high",
                  "PASS" if value == "no" else "FAIL",
                  f"PermitEmptyPasswords = {value}", value, True, ["ssh"])


def check_password_auth():
    cfg = ssh_config()
    value = cfg.get("passwordauthentication", "yes").lower()
    return result("SSH-003", "Disable SSH password authentication", "ssh", "high",
                  "PASS" if value == "no" else "WARN",
                  f"PasswordAuthentication = {value}", value, True, ["ssh", "authentication"])


def check_x11():
    cfg = ssh_config()
    value = cfg.get("x11forwarding", "yes").lower()
    return result("SSH-004", "Disable SSH X11 forwarding", "ssh", "medium",
                  "PASS" if value == "no" else "WARN", f"X11Forwarding = {value}", value, True, ["ssh"])


def check_max_auth():
    cfg = ssh_config()
    raw = cfg.get("maxauthtries", "6")
    try:
        value = int(raw)
    except ValueError:
        value = 99
    return result("SSH-005", "Limit SSH authentication attempts", "ssh", "medium",
                  "PASS" if value <= 4 else "WARN", f"MaxAuthTries = {value}", value, True, ["ssh"])


def check_tcp_forwarding():
    cfg = ssh_config()
    value = cfg.get("allowtcpforwarding", "yes").lower()
    return result("SSH-006", "Review SSH TCP forwarding", "ssh", "medium",
                  "PASS" if value == "no" else "WARN", f"AllowTcpForwarding = {value}", value, True, ["ssh"])


def file_mode(path: str) -> int | None:
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return None


def check_shadow_permissions():
    mode = file_mode("/etc/shadow")
    if mode is None:
        return result("FS-001", "Protect /etc/shadow", "filesystem", "critical", "SKIP", "/etc/shadow not found")
    status = "PASS" if mode <= 0o640 else "FAIL"
    return result("FS-001", "Protect /etc/shadow", "filesystem", "critical", status,
                  f"/etc/shadow mode={oct(mode)}", oct(mode), True, ["filesystem", "permissions"])


def check_passwd_permissions():
    mode = file_mode("/etc/passwd")
    if mode is None:
        return result("FS-002", "Protect /etc/passwd", "filesystem", "high", "SKIP", "/etc/passwd not found")
    status = "PASS" if mode <= 0o644 else "FAIL"
    return result("FS-002", "Protect /etc/passwd", "filesystem", "high", status,
                  f"/etc/passwd mode={oct(mode)}", oct(mode), True, ["filesystem", "permissions"])


def check_world_writable_etc():
    found = []
    root = Path("/etc")
    try:
        for path in root.rglob("*"):
            if len(found) >= 10:
                break
            try:
                mode = stat.S_IMODE(path.stat().st_mode)
            except OSError:
                continue
            if path.is_file() and mode & stat.S_IWOTH:
                found.append(str(path))
    except OSError:
        pass
    return result("FS-003", "Detect world-writable files in /etc", "filesystem", "high",
                  "PASS" if not found else "FAIL",
                  "No world-writable files found" if not found else f"Found {len(found)} world-writable file(s)",
                  found, False, ["filesystem"])


def check_suid_root():
    output = command_output(["find", "/usr", "/bin", "/sbin", "-xdev", "-type", "f", "-perm", "-4000"])
    items = [x for x in output.splitlines() if x][:20]
    return result("FS-004", "Review SUID binaries", "filesystem", "medium", "PASS" if not items else "WARN",
                  f"Detected {len(items)} SUID file(s)" if items else "No SUID files detected",
                  items, False, ["filesystem", "suid"])


def check_ip_forward():
    value = sysctl_value("net.ipv4.ip_forward") or "unknown"
    return result("KERNEL-001", "Disable IPv4 forwarding", "kernel", "medium",
                  "PASS" if value == "0" else "FAIL", f"net.ipv4.ip_forward = {value}", value, True, ["kernel", "sysctl"])


def check_accept_redirects():
    value = sysctl_value("net.ipv4.conf.all.accept_redirects") or "unknown"
    return result("KERNEL-002", "Disable ICMP redirects", "kernel", "medium",
                  "PASS" if value == "0" else "FAIL", f"accept_redirects = {value}", value, True, ["kernel", "sysctl"])


def check_send_redirects():
    value = sysctl_value("net.ipv4.conf.all.send_redirects") or "unknown"
    return result("KERNEL-003", "Disable outbound ICMP redirects", "kernel", "medium",
                  "PASS" if value == "0" else "FAIL", f"send_redirects = {value}", value, True, ["kernel", "sysctl"])


def check_rp_filter():
    value = sysctl_value("net.ipv4.conf.all.rp_filter") or "unknown"
    return result("KERNEL-004", "Enable reverse path filtering", "kernel", "medium",
                  "PASS" if value in {"1", "2"} else "WARN", f"rp_filter = {value}", value, True, ["kernel", "sysctl"])


def check_source_route():
    value = sysctl_value("net.ipv4.conf.all.accept_source_route") or "unknown"
    return result("KERNEL-005", "Disable source routing", "kernel", "high",
                  "PASS" if value == "0" else "FAIL", f"accept_source_route = {value}", value, True, ["kernel", "sysctl"])


def check_syncookies():
    value = sysctl_value("net.ipv4.tcp_syncookies") or "unknown"
    return result("KERNEL-006", "Enable TCP SYN cookies", "kernel", "medium",
                  "PASS" if value == "1" else "WARN", f"tcp_syncookies = {value}", value, True, ["kernel", "sysctl"])


def check_firewall():
    nft = command_output(["nft", "list", "ruleset"])
    ufw = command_output(["ufw", "status"])
    firewalld = command_output(["firewall-cmd", "--state"])
    active = bool(nft.strip() or "Status: active" in ufw or firewalld.strip() == "running")
    return result("FW-001", "Firewall is active", "firewall", "high",
                  "PASS" if active else "WARN", "An active firewall was detected" if active else "No active firewall was detected",
                  {"nft": bool(nft.strip()), "ufw": ufw[:200], "firewalld": firewalld}, False, ["firewall", "network"])


def check_ssh_service():
    output = command_output(["systemctl", "is-active", "ssh"])
    if not output:
        output = command_output(["systemctl", "is-active", "sshd"])
    return result("SERVICE-001", "SSH service state", "services", "medium",
                  "PASS" if output == "active" else "WARN", f"SSH service: {output or 'unknown'}", output, False, ["services", "ssh"])


def check_telnet():
    installed = bool(command_output(["bash", "-lc", "command -v telnetd || dpkg-query -W -f=${Status} telnetd 2>/dev/null | grep -q 'install ok installed'"]))
    return result("SERVICE-002", "Telnet is disabled", "services", "high", "PASS" if not installed else "FAIL",
                  "Telnet daemon not detected" if not installed else "Telnet daemon detected", installed, False, ["services"])


def check_logging():
    journald = command_output(["systemctl", "is-active", "systemd-journald"])
    rsyslog = command_output(["systemctl", "is-active", "rsyslog"])
    active = journald == "active" or rsyslog == "active"
    return result("LOG-001", "System logging service active", "logging", "medium",
                  "PASS" if active else "WARN", "A system logging service is active" if active else "No obvious logging service is active",
                  {"journald": journald, "rsyslog": rsyslog}, False, ["logging"])


def check_auditd():
    active = command_output(["systemctl", "is-active", "auditd"]) == "active"
    installed = bool(command_output(["bash", "-lc", "command -v auditd"]))
    status = "PASS" if active else ("WARN" if installed else "WARN")
    return result("LOG-002", "auditd is present and active", "logging", "medium", status,
                  "auditd is active" if active else ("auditd is installed but inactive" if installed else "auditd not detected"),
                  {"installed": installed, "active": active}, False, ["logging", "audit"])


def check_apparmor_selinux():
    apparmor = command_output(["bash", "-lc", "command -v aa-status && aa-status --enabled"]) 
    selinux = command_output(["getenforce"])
    active = bool(apparmor) or selinux.lower() in {"enforcing", "permissive"}
    return result("MAC-001", "Mandatory access control detected", "mac", "high",
                  "PASS" if active else "WARN", "AppArmor or SELinux is active/detected" if active else "No active AppArmor/SELinux protection detected",
                  {"apparmor": bool(apparmor), "selinux": selinux}, False, ["apparmor", "selinux", "mac"])


def check_ip_listening():
    output = command_output(["ss", "-lntup"])
    lines = [line for line in output.splitlines() if line.strip() and not line.lower().startswith("netid")]
    return result("NET-001", "Review listening network sockets", "network", "medium", "PASS" if len(lines) <= 6 else "WARN",
                  f"{len(lines)} listening socket(s) detected", lines[:25], False, ["network"])


def check_package_updates():
    if not command_output(["bash", "-lc", "command -v apt-get"]):
        return result("PKG-001", "Security package updates available", "packages", "high", "SKIP", "apt-get not available", tags=["packages"])
    output = command_output(["bash", "-lc", "apt list --upgradable 2>/dev/null | tail -n +2"], timeout=15)
    count = len([line for line in output.splitlines() if line.strip()])
    return result("PKG-001", "Review available package updates", "packages", "high", "PASS" if count == 0 else "WARN",
                  "No upgradable packages detected" if count == 0 else f"{count} upgradable package(s) detected", count, False, ["packages", "updates"])


def check_root_accounts():
    roots = []
    for line in read_text("/etc/passwd").splitlines():
        parts = line.split(":")
        if len(parts) >= 3 and parts[2] == "0":
            roots.append(parts[0])
    return result("USER-001", "Limit UID 0 accounts", "accounts", "high", "PASS" if len(roots) == 1 else "FAIL",
                  "Only root has UID 0" if len(roots) == 1 else f"UID 0 accounts: {', '.join(roots)}", roots, False, ["accounts"])


def check_sudo_nopasswd():
    matches = []
    for path in [Path("/etc/sudoers"), Path("/etc/sudoers.d")]:
        if path.is_file():
            text = read_text(str(path))
            if "NOPASSWD:" in text:
                matches.append(str(path))
        elif path.is_dir():
            for child in path.glob("*"):
                text = read_text(str(child))
                if "NOPASSWD:" in text:
                    matches.append(str(child))
    return result("SUDO-001", "Review NOPASSWD sudo rules", "sudo", "high", "PASS" if not matches else "WARN",
                  "No NOPASSWD rules detected" if not matches else f"Found NOPASSWD in {len(matches)} file(s)", matches, False, ["sudo", "privilege"])


def check_world_writable_tmp():
    mode = file_mode("/tmp")
    if mode is None:
        return result("FS-005", "Secure /tmp permissions", "filesystem", "medium", "SKIP", "/tmp not found")
    sticky = bool(mode & stat.S_ISVTX)
    return result("FS-005", "Secure /tmp permissions", "filesystem", "medium", "PASS" if sticky else "FAIL",
                  f"/tmp mode={oct(mode)} sticky={sticky}", oct(mode), True, ["filesystem", "permissions"])


def check_ipv6_redirects():
    value = sysctl_value("net.ipv6.conf.all.accept_redirects") or "unknown"
    return result("KERNEL-007", "Disable IPv6 redirects", "kernel", "medium", "PASS" if value == "0" else "WARN",
                  f"IPv6 accept_redirects = {value}", value, True, ["kernel", "sysctl", "ipv6"])


BUILTIN_CHECKS = {
    f.__name__.replace("check_", ""): f
    for f in [
        check_ssh_root, check_empty_passwords, check_password_auth, check_x11, check_max_auth, check_tcp_forwarding,
        check_shadow_permissions, check_passwd_permissions, check_world_writable_etc, check_suid_root, check_world_writable_tmp,
        check_ip_forward, check_accept_redirects, check_send_redirects, check_rp_filter, check_source_route, check_syncookies, check_ipv6_redirects,
        check_firewall, check_ssh_service, check_telnet, check_logging, check_auditd, check_apparmor_selinux, check_ip_listening,
        check_package_updates, check_root_accounts, check_sudo_nopasswd,
    ]
}
