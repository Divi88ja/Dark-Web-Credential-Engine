"""
MODULE: analytics.py
PURPOSE: Computes aggregated insights for dashboard display.

METRICS PRODUCED:
  - Risk distribution (LOW/MEDIUM/HIGH/CRITICAL counts + percentages)
  - Top risky departments (avg score, employee count, breach rate)
  - Top 10 highest-risk employees
  - Average breach count per department
  - Exposed vs unexposed employee split
  - MFA adoption by risk level

INTERVIEW TALKING POINT:
  "This analytics layer turns raw risk scores into executive-facing KPIs.
   In production, these would feed into a SIEM or GRC dashboard like Splunk or ServiceNow."
"""

import json
from collections import defaultdict
from datetime import datetime


# ─────────────────────────────────────────────
# CORE ANALYTICS FUNCTIONS
# ─────────────────────────────────────────────

def risk_distribution(profiles: list[dict]) -> dict:
    """Count and percentage breakdown by risk level."""
    dist   = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    total  = len(profiles)

    for p in profiles:
        dist[p["risk_level"]] = dist.get(p["risk_level"], 0) + 1

    return {
        "counts":      dist,
        "percentages": {k: round(v / total * 100, 1) if total else 0 for k, v in dist.items()},
        "total":       total,
    }


def department_summary(profiles: list[dict]) -> list[dict]:
    """
    Per-department aggregation:
      - avg_risk_score, max_risk_score
      - employee_count, exposed_count (breach_count > 0)
      - avg_breach_count
      - critical_count, high_count
    Sorted by avg_risk_score descending.
    """
    dept_data = defaultdict(lambda: {
        "scores": [], "breach_counts": [], "exposed": 0,
        "critical": 0, "high": 0, "medium": 0, "low": 0
    })

    for p in profiles:
        d = dept_data[p["department"]]
        d["scores"].append(p["risk_score"])
        d["breach_counts"].append(p["breach_count"])
        if p["breach_count"] > 0:
            d["exposed"] += 1
        d[p["risk_level"].lower()] += 1

    summary = []
    for dept, data in dept_data.items():
        n = len(data["scores"])
        summary.append({
            "department":       dept,
            "employee_count":   n,
            "exposed_count":    data["exposed"],
            "exposure_rate":    round(data["exposed"] / n * 100, 1) if n else 0,
            "avg_risk_score":   round(sum(data["scores"]) / n, 1) if n else 0,
            "max_risk_score":   round(max(data["scores"]), 1) if data["scores"] else 0,
            "avg_breach_count": round(sum(data["breach_counts"]) / n, 2) if n else 0,
            "critical_count":   data["critical"],
            "high_count":       data["high"],
            "medium_count":     data["medium"],
            "low_count":        data["low"],
        })

    return sorted(summary, key=lambda x: -x["avg_risk_score"])


def top_risky_employees(profiles: list[dict], n: int = 10) -> list[dict]:
    """Return the top N highest-risk employees with key fields."""
    sorted_profiles = sorted(profiles, key=lambda x: -x["risk_score"])
    return [
        {
            "rank":              i + 1,
            "name":              p["name"],
            "email":             p["email"],
            "department":        p["department"],
            "role":              p["role"],
            "risk_score":        p["risk_score"],
            "risk_level":        p["risk_level"],
            "breach_count":      p["breach_count"],
            "risk_reason":       p["risk_reason"],
            "mfa_enabled":       p["mfa_enabled"],
        }
        for i, p in enumerate(sorted_profiles[:n])
    ]


def mfa_adoption_by_risk(profiles: list[dict]) -> dict:
    """
    Show MFA adoption rates segmented by risk level.
    Critical/High employees without MFA = most urgent gap.
    """
    result = {}
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cohort   = [p for p in profiles if p["risk_level"] == level]
        with_mfa = sum(1 for p in cohort if p.get("mfa_enabled"))
        n        = len(cohort)
        result[level] = {
            "total":         n,
            "mfa_enabled":   with_mfa,
            "mfa_missing":   n - with_mfa,
            "adoption_pct":  round(with_mfa / n * 100, 1) if n else 0,
        }
    return result


def breach_source_frequency(profiles: list[dict]) -> list[dict]:
    """Rank breach sources by how many employees were exposed."""
    source_counts = defaultdict(int)
    for p in profiles:
        for src in p.get("breach_sources", []):
            source_counts[src] += 1

    return sorted(
        [{"source": k, "exposed_employees": v} for k, v in source_counts.items()],
        key=lambda x: -x["exposed_employees"]
    )


def score_histogram(profiles: list[dict], bins: int = 10) -> list[dict]:
    """Build a score histogram for charting risk distribution curve."""
    width   = 100 / bins
    buckets = [{
        "range":  f"{int(i*width)}–{int((i+1)*width)}",
        "min":    i * width,
        "max":    (i + 1) * width,
        "count":  0
    } for i in range(bins)]

    for p in profiles:
        score = p["risk_score"]
        idx   = min(int(score / width), bins - 1)
        buckets[idx]["count"] += 1

    return buckets


# ─────────────────────────────────────────────
# PIPELINE RUNNER
# ─────────────────────────────────────────────

def run_analytics_pipeline(data_dir: str = "/home/claude/darkweb_intel/data") -> dict:
    with open(f"{data_dir}/risk_profiles.json") as f:
        profiles = json.load(f)

    analytics = {
        "generated_at":            datetime.now().isoformat(),
        "risk_distribution":       risk_distribution(profiles),
        "department_summary":      department_summary(profiles),
        "top_risky_employees":     top_risky_employees(profiles, 10),
        "mfa_adoption_by_risk":    mfa_adoption_by_risk(profiles),
        "breach_source_frequency": breach_source_frequency(profiles),
        "score_histogram":         score_histogram(profiles),
    }

    out_path = f"{data_dir}/analytics.json"
    with open(out_path, "w") as f:
        json.dump(analytics, f, indent=2)

    print(f"[Analytics] Risk dist: {analytics['risk_distribution']['counts']}")
    print(f"[Analytics] Top dept by risk: {analytics['department_summary'][0]['department']}")
    print(f"[Analytics] Results saved → {out_path}")
    return analytics


if __name__ == "__main__":
    run_analytics_pipeline()
