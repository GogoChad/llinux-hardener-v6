from dataclasses import dataclass, asdict, field
from typing import Any


VALID_STATUSES = {"PASS", "FAIL", "WARN", "SKIP", "ERROR"}
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


@dataclass
class CheckResult:
    control_id: str
    title: str
    category: str
    severity: str
    status: str
    message: str
    evidence: Any = None
    fixable: bool = False
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        if data["status"] not in VALID_STATUSES:
            data["status"] = "ERROR"
        if data["severity"] not in VALID_SEVERITIES:
            data["severity"] = "medium"
        return data


@dataclass
class AuditReport:
    hostname: str
    os_name: str
    os_version: str
    score: int
    results: list[CheckResult]

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "score": self.score,
            "results": [r.to_dict() for r in self.results],
        }
