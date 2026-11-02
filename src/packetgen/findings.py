"""The one finding shape every check returns."""
from __future__ import annotations


def finding(check: str, message: str, fix: str, severity: str = "error") -> dict:
    return {"check": check, "message": message, "fix": fix, "severity": severity}


def has_errors(findings: list[dict]) -> bool:
    return any(f["severity"] == "error" for f in findings)
