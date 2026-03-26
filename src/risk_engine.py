"""
MODULE: risk_engine.py
PURPOSE: Multi-factor, explainable risk scoring engine.

DESIGN PHILOSOPHY:
  Avoid flat/identical scores by computing a WEIGHTED SUM of independent
  sub-scores, then applying sigmoid normalization to produce a realistic
  0–100 distribution.

SUB-SCORES (each 0–100 internally, then weighted):
  1. breach_score    — how many breaches, how severe
  2. recency_score   — how recently exposed (recent = riskier)
  3. role_score      — seniority × department criticality
  4. exposure_score  — plaintext passwords, high-confidence leaks

RISK LEVELS:
  CRITICAL  90–100  → Immediate incident response
  HIGH      70–89   → Urgent remediation within 24h
  MEDIUM    40–69   → Scheduled review within 7 days
  LOW        0–39   → Monitor, routine hygiene

INTERVIEW TALKING POINT:
  "Unlike static rule-based systems, this engine computes orthogonal
   risk dimensions and combines them with domain-tuned weights —
   mimicking how security analysts triage alerts in practice."
"""

import json
import math
from datetime import datetime
from pathlib import Path
from collections import defaultdict


# ─────────────────────────────────────────────
# WEIGHTS (must sum to 1.0)
# ─────────────────────────────────────────────

WEIGHTS = {
    "breach_score":   0.35,   # Volume + severity of breaches
    "recency_score":  0.25,   # How recently exposed
    "role_score":     0.25,   # Privilege level × department criticality
    "exposure_score": 0.15,   # Plaintext passwords, high-confidence hits
}

SEVERITY_MAP = {"minor": 10, "moderate": 30, "major": 60, "critical": 90}
RECENCY_DECAY = 365  # Days at which recency risk halves


# ─────────────────────────────────────────────
# SUB-SCORE FUNCTIONS
# ─────────────────────────────────────────────

def compute_breach_score(breach_records: list[dict]) -> float:
    """
    Score based on:
      - Number of unique breaches (log-scaled to avoid runaway)
      - Cumulative severity weight
    Returns 0–100.
    """
    if not breach_records:
        return 0.0

    count           = len(breach_records)
    severity_total  = sum(SEVERITY_MAP.get(r["breach_severity"], 20) for r in breach_records)
    severity_avg    = severity_total / count

    # Log scaling: first breach has high impact; additional breaches add diminishing returns
    count_factor    = min(100, math.log1p(count) / math.log1p(8) * 100)

    # Blend count factor with average severity
    raw = (count_factor * 0.5) + (severity_avg * 0.5)
    return min(round(raw, 2), 100.0)


def compute_recency_score(breach_records: list[dict]) -> float:
    """
    Score based on the most recent breach date.
    Exponential decay: breach yesterday = ~100, breach 2yr ago = ~30.
    Returns 0–100.
    """
    if not breach_records:
        return 0.0

    # Use minimum days_since (most recent breach)
    min_days = min(r.get("days_since", 365) for r in breach_records)

    # Exponential decay formula: score = 100 × e^(-λt) where λ = ln(2)/half_life
    half_life = RECENCY_DECAY
    lam       = math.log(2) / half_life
    raw       = 100 * math.exp(-lam * min_days)

    return round(raw, 2)


def compute_role_score(employee: dict) -> float:
    """
    Score based on:
      - Role sensitivity (0–1 scale from ROLE_SENSITIVITY dict)
      - Department criticality (0–1 scale)
    Geometric mean gives balanced weighting — penalizes weak entries in either dimension.
    Returns 0–100.
    """
    role_s = employee.get("role_sensitivity", 0.5)
    dept_c = employee.get("dept_criticality", 0.5)

    # Geometric mean amplifies risk when BOTH are high
    geo_mean = math.sqrt(role_s * dept_c)
    return round(geo_mean * 100, 2)


def compute_exposure_score(breach_records: list[dict]) -> float:
    """
    Bonus risk for high-confidence exposure signals:
      - Plaintext passwords found in breach data
      - Critical severity breach with password data types
    Returns 0–100.
    """
    if not breach_records:
        return 0.0

    plaintext_hits    = sum(1 for r in breach_records if r.get("plaintext_pw", False))
    critical_count    = sum(1 for r in breach_records if r.get("breach_severity") == "critical")

    plaintext_factor  = min(100, plaintext_hits * 35)
    critical_factor   = min(60,  critical_count * 20)

    raw = (plaintext_factor * 0.6) + (critical_factor * 0.4)
    return round(min(raw, 100), 2)


# ─────────────────────────────────────────────
# COMPOSITE SCORE + EXPLAINABILITY
# ─────────────────────────────────────────────

def compute_risk(employee: dict, breach_records: list[dict]) -> dict:
    """
    Compute the full risk profile for one employee.

    Returns a dict with:
      - Composite risk_score (0–100)
      - risk_level (LOW / MEDIUM / HIGH / CRITICAL)
      - Sub-scores for each dimension
      - risk_reason: human-readable explanation
      - recommended_action
    """
    scores = {
        "breach_score":   compute_breach_score(breach_records),
        "recency_score":  compute_recency_score(breach_records),
        "role_score":     compute_role_score(employee),
        "exposure_score": compute_exposure_score(breach_records),
    }

    # Weighted composite
    composite = sum(scores[k] * WEIGHTS[k] for k in scores)

    # Apply a mild sigmoid stretch to push scores toward the extremes
    # (avoids everyone clustering in the 40–60 band)
    composite = _sigmoid_stretch(composite)
    composite = round(min(max(composite, 0), 100), 1)

    risk_level = _risk_level(composite)
    reason     = _build_reason(employee, breach_records, scores, composite)
    action     = _recommended_action(risk_level, employee, breach_records)

    # Breach source list
    sources = list({r["breach_source"] for r in breach_records})

    return {
        "employee_id":       employee["employee_id"],
        "name":              employee["name"],
        "email":             employee["email"],
        "department":        employee["department"],
        "role":              employee["role"],
        "risk_score":        composite,
        "risk_level":        risk_level,
        "breach_count":      len(breach_records),
        "breach_sources":    sources,
        "breach_score":      scores["breach_score"],
        "recency_score":     scores["recency_score"],
        "role_score":        scores["role_score"],
        "exposure_score":    scores["exposure_score"],
        "mfa_enabled":       employee.get("mfa_enabled", False),
        "risk_reason":       reason,
        "recommended_action":action,
        "scored_at":         datetime.now().isoformat(),
    }


def _sigmoid_stretch(x: float, center: float = 50, steepness: float = 0.06) -> float:
    """
    Stretch scores away from the midpoint using a logistic function.
    Prevents scores from clustering at 40–60 and creates cleaner risk bands.
    """
    shifted = x - center
    stretched = 100 / (1 + math.exp(-steepness * shifted * 2))
    # Blend 60% stretched + 40% original to preserve linearity at extremes
    return (stretched * 0.6) + (x * 0.4)


def _risk_level(score: float) -> str:
    if score >= 90: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


def _build_reason(employee: dict, breach_records: list[dict], scores: dict, composite: float) -> str:
    """
    Build a human-readable explanation of the risk score.
    Surfaces the top contributing factors dynamically.
    """
    reasons = []

    # Breach count
    n = len(breach_records)
    if n == 0:
        return "No breach exposure detected."
    elif n == 1:
        reasons.append("Found in 1 breach")
    else:
        reasons.append(f"Exposed in {n} breaches")

    # Severity
    severities = [r["breach_severity"] for r in breach_records]
    critical_n = severities.count("critical")
    major_n    = severities.count("major")
    if critical_n > 0:
        reasons.append(f"{critical_n} critical-severity leak(s)")
    elif major_n > 0:
        reasons.append(f"{major_n} major leak(s)")

    # Recency
    min_days = min((r.get("days_since", 999) for r in breach_records), default=999)
    if min_days < 90:
        reasons.append("very recent exposure (<90 days)")
    elif min_days < 180:
        reasons.append("recent exposure (<6 months)")

    # Role
    if employee.get("role_sensitivity", 0) >= 0.85:
        reasons.append(f"high-privilege role ({employee['role']})")
    elif employee.get("dept_criticality", 0) >= 0.90:
        reasons.append(f"critical department ({employee['department']})")

    # Plaintext
    pt = sum(1 for r in breach_records if r.get("plaintext_pw"))
    if pt > 0:
        reasons.append(f"plaintext password in {pt} source(s)")

    # MFA
    if not employee.get("mfa_enabled"):
        reasons.append("MFA not enabled")

    return " | ".join(reasons)


def _recommended_action(risk_level: str, employee: dict, breach_records: list[dict]) -> str:
    """Return a prioritized recommended remediation action."""
    actions = []

    if risk_level in ("CRITICAL", "HIGH"):
        actions.append("🔴 Force immediate password reset")
        if not employee.get("mfa_enabled"):
            actions.append("Enable MFA now")
        actions.append("Review account access logs")
    elif risk_level == "MEDIUM":
        actions.append("🟡 Schedule password reset within 7 days")
        if not employee.get("mfa_enabled"):
            actions.append("Enroll in MFA program")
        actions.append("Security awareness training")
    else:
        actions.append("🟢 Monitor — routine password hygiene at next cycle")

    if any(r.get("plaintext_pw") for r in breach_records):
        actions.insert(0, "⚠️ URGENT: Plaintext password exposed — reset immediately")

    return " | ".join(actions)


# ─────────────────────────────────────────────
# BATCH SCORING
# ─────────────────────────────────────────────

def score_all_employees(employees: list[dict], breach_records: list[dict]) -> list[dict]:
    """
    Score every employee. Employees with zero breaches still receive a profile
    (risk_score=0, risk_level=LOW) to ensure complete coverage in the dashboard.
    """
    # Group breach records by employee_id for O(1) lookup
    breach_map = defaultdict(list)
    for r in breach_records:
        breach_map[r["employee_id"]].append(r)

    scored = []
    for emp in employees:
        emp_breaches = breach_map.get(emp["employee_id"], [])
        scored.append(compute_risk(emp, emp_breaches))

    # Sort by risk_score descending for dashboard display
    scored.sort(key=lambda x: x["risk_score"], reverse=True)
    return scored


# ─────────────────────────────────────────────
# EMAIL LOOKUP (HIBP-STYLE API)
# ─────────────────────────────────────────────

def get_user_risk(email: str, scored_profiles: list[dict]) -> dict:
    """
    HIBP-style lookup: given an email, return the full risk profile.

    Args:
        email: The corporate email to look up
        scored_profiles: Pre-scored profiles list from score_all_employees()

    Returns:
        Risk profile dict or a 'not found' response.
    """
    email = email.strip().lower()
    for profile in scored_profiles:
        if profile["email"].lower() == email:
            return {
                "status":             "FOUND",
                "email":              profile["email"],
                "name":               profile["name"],
                "risk_score":         profile["risk_score"],
                "risk_level":         profile["risk_level"],
                "breach_count":       profile["breach_count"],
                "breach_sources":     profile["breach_sources"],
                "risk_reason":        profile["risk_reason"],
                "recommended_action": profile["recommended_action"],
                "sub_scores": {
                    "breach_score":   profile["breach_score"],
                    "recency_score":  profile["recency_score"],
                    "role_score":     profile["role_score"],
                    "exposure_score": profile["exposure_score"],
                },
                "mfa_enabled": profile["mfa_enabled"],
            }

    return {
        "status":      "NOT_FOUND",
        "email":       email,
        "risk_score":  0,
        "risk_level":  "UNKNOWN",
        "breach_count":0,
        "message":     "Email not found in employee registry or breach database.",
    }


# ─────────────────────────────────────────────
# PIPELINE RUNNER
# ─────────────────────────────────────────────

def run_scoring_pipeline(data_dir: str = "/home/claude/darkweb_intel/data") -> list[dict]:
    with open(f"{data_dir}/employees.json")      as f: employees = json.load(f)
    with open(f"{data_dir}/breach_records.json") as f: breaches  = json.load(f)

    print(f"[RiskEngine] Scoring {len(employees)} employees against {len(breaches)} breach records...")
    profiles = score_all_employees(employees, breaches)

    out_path = f"{data_dir}/risk_profiles.json"
    with open(out_path, "w") as f:
        json.dump(profiles, f, indent=2)

    # Distribution summary
    dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for p in profiles:
        dist[p["risk_level"]] = dist.get(p["risk_level"], 0) + 1

    print(f"[RiskEngine] Score distribution: {dist}")
    print(f"[RiskEngine] Profiles saved → {out_path}")
    return profiles


if __name__ == "__main__":
    run_scoring_pipeline()
