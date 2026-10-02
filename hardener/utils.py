from pathlib import Path
import os
import platform
import subprocess


def read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def command_output(command: list[str], timeout: int = 5) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return (result.stdout + result.stderr).strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def command_ok(command: list[str], timeout: int = 5) -> bool:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            check=False,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def is_root() -> bool:
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def detect_os() -> tuple[str, str]:
    values = {}
    for line in read_text("/etc/os-release").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    name = values.get("PRETTY_NAME", values.get("ID", platform.system()))
    version = values.get("VERSION_ID", platform.release())
    return name, version


def sysctl_value(key: str) -> str | None:
    output = command_output(["sysctl", "-n", key])
    return output.splitlines()[0].strip() if output else None


def parse_key_values(text: str) -> dict[str, str]:
    data = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if " " in line:
            key, value = line.split(None, 1)
            data[key] = value.strip()
    return data
