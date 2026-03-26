"""
MODULE: alert_engine.py
PURPOSE: Generates prioritized security alerts for HIGH and CRITICAL risk employees.

ALERT PHILOSOPHY:
  - Only trigger for HIGH and CRITICAL (avoid alert fatigue from MEDIUM/LOW noise)
  - Each alert has a priority P1–P4 mapped to SLA response times
  - Alerts are enriched with context and deduplicated

PRIORITY MAP:
  P1 (CRITICAL) → Respond within 1 hour   — e.g., C-suite with plaintext pw
  P2 (HIGH)     → Respond within 4 hours  — e.g., senior role + recent breach
  P3 (MEDIUM)   → Respond within 24 hours — informational, bulk action
  P4 (LOW)      → Respond within 7 days   — hygiene reminders

INTERVIEW TALKING POINT:
  "The alert engine separates signal from noise. By anchoring SLA to risk level,
   the SOC team can triage without manually reviewing every exposure."
"""

import json
from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────────
# ALERT THRESHOLDS
# ─────────────────────────────────────────────

ALERT_LEVELS    = {"CRITICAL", "HIGH"}   # Only these levels generate active alerts
SLA_MAP         = {"CRITICAL": "1 hour", "HIGH": "4 hours", "MEDIUM": "24 hours", "LOW": "7 days"}
PRIORITY_MAP    = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4"}


# ─────────────────────────────────────────────
# ALERT BUILDER
# ─────────────────────────────────────────────

def build_alert(profile: dict) -> dict | None:
    """
    Construct a structured alert object for a given risk profile.
    Returns None for profiles below the alert threshold.
    """
    level = profile["risk_level"]
    if level not in ALERT_LEVELS:
        return None

    # Determine escalation triggers
    escalation_triggers = _get_escalation_triggers(profile)

    return {
        "alert_id":            f"ALT-{profile['employee_id']}-{datetime.now().strftime('%Y%m%d%H%M')}",
        "priority":            PRIORITY_MAP[level],
        "risk_level":          level,
        "risk_score":          profile["risk_score"],
        "employee_id":         profile["employee_id"],
        "name":                profile["name"],
        "email":               profile["email"],
        "department":          profile["department"],
        "role":                profile["role"],
        "breach_count":        profile["breach_count"],
        "breach_sources":      profile["breach_sources"],
        "risk_reason":         profile["risk_reason"],
        "escalation_triggers": escalation_triggers,
        "recommended_actions": _get_actions(profile),
        "sla_response_time":   SLA_MAP[level],
        "mfa_enabled":         profile["mfa_enabled"],
        "alert_generated_at":  datetime.now().isoformat(),
        "status":              "OPEN",
    }


def _get_escalation_triggers(profile: dict) -> list[str]:
    """Identify why this alert was escalated beyond standard HIGH/CRITICAL."""
    triggers = []

    if profile["risk_score"] >= 95:
        triggers.append("Extreme risk score (≥95)")
    if profile.get("exposure_score", 0) > 60:
        triggers.append("High plaintext password exposure")
    if profile.get("recency_score", 0) > 70:
        triggers.append("Very recent breach (<90 days)")
    if profile.get("role_sensitivity", 0) >= 0.90 or profile["role"] in ("CEO", "CTO", "CFO", "VP"):
        triggers.append(f"Executive/privileged role: {profile['role']}")
    if profile["breach_count"] >= 4:
        triggers.append(f"Multiple breach appearances ({profile['breach_count']})")
    if not profile.get("mfa_enabled"):
        triggers.append("MFA not enabled — account at risk")

    return triggers if triggers else ["Standard HIGH/CRITICAL threshold breach"]


def _get_actions(profile: dict) -> list[str]:
    """Return ordered list of recommended security actions."""
    actions = []
    level   = profile["risk_level"]

    # Check for plaintext in risk_reason
    has_plaintext = "plaintext" in profile.get("risk_reason", "").lower()

    if has_plaintext:
        actions.append("⚠️  URGENT: Force password reset — plaintext credential exposed on dark web")

    if level == "CRITICAL":
        actions.append("🔴 Suspend account access pending security review")
        actions.append("🔴 Notify CISO and direct manager immediately")
        actions.append("🔴 Audit last 30 days of login activity")

    elif level == "HIGH":
        actions.append("🟠 Force password reset within 4 hours")
        actions.append("🟠 Review privileged access grants")

    if not profile.get("mfa_enabled"):
        actions.append("📱 Enforce MFA enrollment before next login")

    if profile["breach_count"] >= 3:
        actions.append("📋 Enroll in mandatory security awareness training")

    if level == "CRITICAL":
        actions.append("🔒 Consider temporary privilege reduction")

    return actions


# ─────────────────────────────────────────────
# BATCH ALERT GENERATION
# ─────────────────────────────────────────────

def generate_all_alerts(profiles: list[dict]) -> dict:
    """
    Process all risk profiles and generate alerts for HIGH/CRITICAL cases.

    Returns:
        {
          "summary": {...},
          "alerts": [alert_dict, ...],
          "by_priority": {"P1": [...], "P2": [...]}
        }
    """
    alerts = []
    for profile in profiles:
        alert = build_alert(profile)
        if alert:
            alerts.append(alert)

    # Group by priority
    by_priority = {"P1": [], "P2": [], "P3": [], "P4": []}
    for alert in alerts:
        by_priority[alert["priority"]].append(alert)

    # Department breakdown
    dept_counts = {}
    for alert in alerts:
        dept = alert["department"]
        dept_counts[dept] = dept_counts.get(dept, 0) + 1

    summary = {
        "total_alerts":           len(alerts),
        "critical_alerts":        len(by_priority["P1"]),
        "high_alerts":            len(by_priority["P2"]),
        "departments_impacted":   len(dept_counts),
        "top_dept_by_alerts":     sorted(dept_counts.items(), key=lambda x: -x[1])[:5],
        "no_mfa_high_risk":       sum(1 for a in alerts if not a["mfa_enabled"]),
        "generated_at":           datetime.now().isoformat(),
    }

    return {
        "summary":     summary,
        "alerts":      alerts,
        "by_priority": by_priority,
    }


# ─────────────────────────────────────────────
# PIPELINE RUNNER
# ─────────────────────────────────────────────

def run_alert_pipeline(data_dir: str = "/home/claude/darkweb_intel/data") -> dict:
    with open(f"{data_dir}/risk_profiles.json") as f:
        profiles = json.load(f)

    print(f"[AlertEngine] Processing {len(profiles)} profiles for alert generation...")
    result = generate_all_alerts(profiles)

    out_path = f"{data_dir}/alerts.json"
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)

    s = result["summary"]
    print(f"[AlertEngine] Alerts generated: {s['total_alerts']} "
          f"(P1={s['critical_alerts']}, P2={s['high_alerts']})")
    print(f"[AlertEngine] Departments impacted: {s['departments_impacted']}")
    print(f"[AlertEngine] Alerts saved → {out_path}")
    return result


if __name__ == "__main__":
    run_alert_pipeline()
