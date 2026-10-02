from .checks.builtin import BUILTIN_CHECKS

CONTROL_MAP = {
    "SSH-001": "ssh_root",
    "SSH-002": "empty_passwords",
    "SSH-003": "password_auth",
    "SSH-004": "x11",
    "SSH-005": "max_auth",
    "SSH-006": "tcp_forwarding",
    "FS-001": "shadow_permissions",
    "FS-002": "passwd_permissions",
    "FS-003": "world_writable_etc",
    "FS-004": "suid_root",
    "FS-005": "world_writable_tmp",
    "KERNEL-001": "ip_forward",
    "KERNEL-002": "accept_redirects",
    "KERNEL-003": "send_redirects",
    "KERNEL-004": "rp_filter",
    "KERNEL-005": "source_route",
    "KERNEL-006": "syncookies",
    "KERNEL-007": "ipv6_redirects",
    "FW-001": "firewall",
    "SERVICE-001": "ssh_service",
    "SERVICE-002": "telnet",
    "LOG-001": "logging",
    "LOG-002": "auditd",
    "MAC-001": "apparmor_selinux",
    "NET-001": "ip_listening",
    "PKG-001": "package_updates",
    "USER-001": "root_accounts",
    "SUDO-001": "sudo_nopasswd",
}


def available_ids() -> list[str]:
    return list(CONTROL_MAP)


def run_control(control_id: str):
    name = CONTROL_MAP[control_id]
    return BUILTIN_CHECKS[name]()
