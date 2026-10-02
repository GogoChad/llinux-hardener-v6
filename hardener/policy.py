from pathlib import Path
import yaml

DEFAULT_POLICY = {
    "name": "server",
    "enabled": [],
}


def load_policy(path: str | None) -> dict:
    if not path:
        return DEFAULT_POLICY.copy()
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return data


def selected_controls(policy: dict, available_ids: list[str]) -> list[str]:
    enabled = policy.get("enabled") or []
    disabled = set(policy.get("disabled") or [])
    if not enabled:
        return [cid for cid in available_ids if cid not in disabled]
    return [cid for cid in enabled if cid in available_ids and cid not in disabled]
