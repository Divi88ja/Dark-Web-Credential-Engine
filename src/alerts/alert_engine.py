"""
alerts/alert_engine.py
-----------------------
Automated Security Alert Generator.

Reads risk-scored employee data, flags employees above the threshold,
generates structured alerts with recommended actions, and outputs them
to JSON/CSV for consumption by dashboards, SIEM, or email systems.

Design decision: Alerts are data-first (JSON) so they can be consumed
by any downstream system (Slack webhook, PagerDuty, email, SIEM).
"""

import os
import json
import pandas as pd
from datetime import datetime
from typing import List, Dict
from src.utils.helpers import setup_logger, load_config, save_json, current_timestamp

logger = setup_logger(__name__)


# ── Action templates keyed by risk level ──────────────────────
RECOMMENDED_ACTIONS = {
    "CRITICAL": [
        "IMMEDIATE: Force password reset now",
        "IMMEDIATE: Disable account pending review",
        "Enable MFA if not already active",
        "Notify security team for manual investigation",
        "Review last 30 days of account activity",
        "Check for unauthorized access or data exfiltration",
    ],
    "HIGH": [
        "Force password reset within 4 hours",
        "Enable MFA",
        "Security team notification",
        "Review account activity for anomalies",
    ],
    "MEDIUM": [
        "Request voluntary password reset within 24 hours",
        "Recommend MFA enrollment",
        "Add to watchlist for monitoring",
    ],
    "LOW": [
        "Send security awareness notification to user",
        "Schedule routine security review",
    ],
}


class AlertEngine:
    """
    Generate, format, and save security alerts.

    Usage:
        engine = AlertEngine()
        alerts = engine.generate_alerts(risk_scored_df)
        engine.save_alerts(alerts)
        engine.print_summary(alerts)
    """

    def __init__(self, config_path: str = "configs/config.yaml"):
        cfg = load_config(config_path)
        self.threshold    = cfg["alerts"]["risk_threshold"]
        self.output_path  = cfg["alerts"]["output_path"]

    def generate_alerts(self, df: pd.DataFrame) -> List[Dict]:
        """
        Generate alert objects for all employees above the risk threshold.
        
        Returns a list of alert dicts — one per high-risk employee.
        """
        if "risk_score" not in df.columns:
            raise ValueError("DataFrame must have 'risk_score' column. Run RiskScorer.score() first.")

        # Filter to employees at or above the threshold
        alert_df = df[df["risk_score"] >= self.threshold].copy()
        alert_df = alert_df.sort_values("risk_score", ascending=False)

        alerts = []
        for _, row in alert_df.iterrows():
            alert = self._build_alert(row)
            alerts.append(alert)

        logger.info(f"Generated {len(alerts)} alerts (threshold: {self.threshold})")
        return alerts

    def _build_alert(self, row: pd.Series) -> Dict:
        """Build a single structured alert for one employee."""
        risk_level = str(row.get("risk_level", "HIGH"))
        actions    = RECOMMENDED_ACTIONS.get(risk_level, RECOMMENDED_ACTIONS["HIGH"])

        return {
            "alert_id":         f"ALERT-{current_timestamp()}-{row.get('employee_id', 'UNKNOWN')}",
            "generated_at":     datetime.now().isoformat(),
            "severity":         risk_level,
            "risk_score":       float(row.get("risk_score", 0)),
            "employee": {
                "id":           row.get("employee_id", ""),
                "name":         row.get("full_name", ""),
                "email":        row.get("email", ""),
                "department":   row.get("department", ""),
                "role":         row.get("role", ""),
            },
            "breach_details": {
                "breach_count":         int(row.get("breach_count", 0)),
                "breach_sources":       row.get("breach_sources", ""),
                "latest_breach_date":   row.get("latest_breach_date", ""),
                "earliest_breach_date": row.get("earliest_breach_date", ""),
                "match_types":          row.get("match_types", ""),
                "password_reuse":       int(row.get("password_reuse_count", 0)),
                "sensitive_keywords":   bool(row.get("has_sensitive_keyword", False)),
            },
            "explanation":          row.get("risk_explanation", ""),
            "recommended_actions":  actions,
            "status":               "OPEN",
        }

    def save_alerts(self, alerts: List[Dict]) -> str:
        """Save alerts to JSON file. Returns the output path."""
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        save_json(alerts, self.output_path)

        # Also save as CSV for easy Excel viewing
        csv_path = self.output_path.replace(".json", ".csv")
        if alerts:
            flat_alerts = []
            for a in alerts:
                flat = {
                    "alert_id":      a["alert_id"],
                    "generated_at":  a["generated_at"],
                    "severity":      a["severity"],
                    "risk_score":    a["risk_score"],
                    "employee_id":   a["employee"]["id"],
                    "name":          a["employee"]["name"],
                    "email":         a["employee"]["email"],
                    "department":    a["employee"]["department"],
                    "role":          a["employee"]["role"],
                    "breach_count":  a["breach_details"]["breach_count"],
                    "breach_sources":a["breach_details"]["breach_sources"],
                    "explanation":   a["explanation"],
                    "top_action":    a["recommended_actions"][0] if a["recommended_actions"] else "",
                }
                flat_alerts.append(flat)
            pd.DataFrame(flat_alerts).to_csv(csv_path, index=False)

        logger.info(f"Alerts saved → {self.output_path} and {csv_path}")
        return self.output_path

    def print_summary(self, alerts: List[Dict]) -> None:
        """Print a human-readable alert summary to console."""
        if not alerts:
            print("\n✓ No alerts generated — all employees below risk threshold.\n")
            return

        print(f"\n{'='*60}")
        print(f"  SECURITY ALERT SUMMARY  |  {len(alerts)} alerts generated")
        print(f"{'='*60}")

        # Count by severity
        from collections import Counter
        severity_counts = Counter(a["severity"] for a in alerts)
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if level in severity_counts:
                print(f"  {level:10s}: {severity_counts[level]} employees")

        print(f"\n  TOP 5 HIGHEST RISK:")
        print(f"  {'Employee':<25} {'Risk':<8} {'Dept':<15} {'Breaches'}")
        print(f"  {'-'*60}")
        for alert in alerts[:5]:
            emp  = alert["employee"]
            bd   = alert["breach_details"]
            print(f"  {emp['name']:<25} {alert['risk_score']:<8.1f} "
                  f"{emp['department']:<15} {bd['breach_count']}")

        print(f"\n  Alerts saved to: {self.output_path}")
        print(f"{'='*60}\n")

    def get_department_summary(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Aggregate risk by department — useful for dashboard visualization.
        """
        if "department" not in df.columns or "risk_score" not in df.columns:
            return pd.DataFrame()

        summary = df.groupby("department").agg(
            total_employees  = ("employee_id", "count"),
            compromised      = ("is_compromised", "sum"),
            avg_risk_score   = ("risk_score", "mean"),
            max_risk_score   = ("risk_score", "max"),
            critical_count   = ("risk_level", lambda x: (x == "CRITICAL").sum()),
            high_count       = ("risk_level", lambda x: (x == "HIGH").sum()),
        ).reset_index()

        summary["exposure_rate"] = (
            summary["compromised"] / summary["total_employees"] * 100
        ).round(1)

        return summary.sort_values("avg_risk_score", ascending=False)
