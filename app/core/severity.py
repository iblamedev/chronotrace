"""Severity resolution engine.

Resolves final alert severity from (base rule severity) + (correlation escalation)
without mutating the original rule's configured severity.

Rules:
1. Behavioral detections retain their assigned severity (e.g. CRITICAL for brute-force).
2. If an event is part of a correlated pattern:
   - If part of a CRITICAL brute force or high-volume attack, signature alerts on that IP
     can be escalated (e.g. LOW failed-login or MEDIUM probe escalated to HIGH/CRITICAL).
3. If an IP has multiple high/critical detections, low-severity events can be escalated to MEDIUM.
"""

from __future__ import annotations

from app.models.detection import DetectionResult
from app.models.rule import DetectionMethod, Severity


def resolve_severity(
    detection: DetectionResult,
    correlated_detections: list[DetectionResult] | None = None,
) -> Severity:
    """Returns the resolved final Severity for a detection given correlation context."""
    # 1. Behavioral detections define their own evaluated severity
    if detection.method == DetectionMethod.BEHAVIORAL:
        return detection.severity

    base_sev = detection.severity
    if not correlated_detections:
        return base_sev

    ip = detection.event.source_ip
    if not ip:
        return base_sev

    # Check if there is a behavioral detection for this same IP
    ip_behavioral = [
        d
        for d in correlated_detections
        if d.method == DetectionMethod.BEHAVIORAL and d.event.source_ip == ip
    ]

    has_brute_force = any(d.rule_id == "behavioral-brute-force" for d in ip_behavioral)
    has_multi_cat = any(d.rule_id == "behavioral-multi-category" for d in ip_behavioral)
    has_scanner = any(d.rule_id == "behavioral-scanner-recon" for d in ip_behavioral)

    # Escalation logic
    if has_brute_force:
        # Failed login / auth probes escalate to HIGH or CRITICAL
        if detection.rule_id in (
            "failed-login",
            "multi-failed-login",
            "credential-stuffing-probe",
        ):
            return Severity.HIGH if base_sev.rank < Severity.HIGH.rank else base_sev
        if detection.rule_id in ("error-denied", "repeated-4xx-5xx"):
            return Severity.MEDIUM

    if has_multi_cat:
        # Coordinated attacker: escalate LOW/INFO signatures to at least MEDIUM
        if base_sev in (Severity.INFO, Severity.LOW):
            return Severity.MEDIUM
        if base_sev == Severity.MEDIUM:
            return Severity.HIGH

    if has_scanner and detection.rule_id in (
        "discovery-recon",
        "scanner-ua",
        "default-admin-probe",
    ):
        return Severity.HIGH if base_sev == Severity.MEDIUM else base_sev

    return base_sev
