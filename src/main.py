import sys
import json
import argparse
from pathlib import Path

# Ensure modules are importable
sys.path.insert(0, str(Path(__file__).parent / "src"))

from data_generator import save_datasets
from nlp_extractor import run_nlp_pipeline
from risk_engine import run_scoring_pipeline, get_user_risk
from alert_engine import run_alert_pipeline
from analytics import run_analytics_pipeline

DATA_DIR = str(Path(__file__).parent / "data")


# ─────────────────────────────────────────────
# FULL PIPELINE
# ─────────────────────────────────────────────
def run_full_pipeline():
    print("\n" + "=" * 60)
    print("  DARK WEB CREDENTIAL INTELLIGENCE PLATFORM")
    print("  Enterprise Security Monitoring System v2.1")
    print("=" * 60 + "\n")

    # Step 1: Data Ingestion
    print("── STEP 1: Data Ingestion ──────────────────────────────")
    save_datasets(DATA_DIR)

    # Step 2: NLP Extraction
    print("\n── STEP 2: NLP Entity Extraction ───────────────────────")
    nlp_results = run_nlp_pipeline(DATA_DIR)

    # Step 3: Risk Scoring
    print("\n── STEP 3: Risk Scoring Engine ─────────────────────────")
    profiles = run_scoring_pipeline(DATA_DIR)

    # Step 4: Alert Generation
    print("\n── STEP 4: Alert Generation ────────────────────────────")
    alerts = run_alert_pipeline(DATA_DIR)

    # Step 5: Analytics
    print("\n── STEP 5: Analytics Aggregation ───────────────────────")
    analytics = run_analytics_pipeline(DATA_DIR)

    # Summary report
    dist = analytics["risk_distribution"]

    print("\n" + "=" * 60)
    print("  PIPELINE COMPLETE — SUMMARY REPORT")
    print("=" * 60)

    print(f"  Total employees analyzed : {dist['total']}")
    print(f"  CRITICAL risk            : {dist['counts']['CRITICAL']} ({dist['percentages']['CRITICAL']}%)")
    print(f"  HIGH risk                : {dist['counts']['HIGH']} ({dist['percentages']['HIGH']}%)")
    print(f"  MEDIUM risk              : {dist['counts']['MEDIUM']} ({dist['percentages']['MEDIUM']}%)")
    print(f"  LOW risk                 : {dist['counts']['LOW']} ({dist['percentages']['LOW']}%)")

    print(f"  Active alerts (P1+P2)    : {alerts['summary']['total_alerts']}")
    print(f"  NLP email hits           : {nlp_results['total_emails_found']}")

    print("\n  ✔ Data Source: Simulated + Public Breach Intelligence (HIBP-ready)")

    print("=" * 60 + "\n")


# ─────────────────────────────────────────────
# EMAIL LOOKUP (HIBP STYLE)
# ─────────────────────────────────────────────
def lookup_email(email: str):
    """CLI email lookup — HIBP-style."""

    profiles_path = f"{DATA_DIR}/risk_profiles.json"

    if not Path(profiles_path).exists():
        print("[ERROR] Run full pipeline first: python main.py")
        return

    with open(profiles_path) as f:
        profiles = json.load(f)

    result = get_user_risk(email, profiles)

    print(f"\n{'=' * 60}")
    print(f"  EMAIL RISK LOOKUP")
    print(f"{'=' * 60}")
    print(f"  Email: {email}")
    print(f"{'-' * 60}")

    if result["status"] == "NOT_FOUND":
        print(f"  Status    : {result['status']}")
        print(f"  Message   : {result['message']}")

    else:
        print(f"  Status         : {result['status']}")
        print(f"  Name           : {result['name']}")
        print(f"  Risk Score     : {result['risk_score']}/100")
        print(f"  Risk Level     : {result['risk_level']}")
        print(f"  Breach Count   : {result['breach_count']}")
        print(f"  MFA Enabled    : {result['mfa_enabled']}")

        print(f"\n  Breach Sources:")
        if result["breach_sources"]:
            for src in result["breach_sources"]:
                print(f"    - {src}")
        else:
            print("    None")

        print(f"\n  🔍 Risk Explanation:")
        print(f"    {result.get('risk_explanation', result.get('risk_reason', 'N/A'))}")

        print(f"\n  ⚡ Recommended Action:")
        actions = result.get("recommended_action", "")
        for action in actions.split(" | "):
            print(f"    → {action}")

        print(f"\n  Sub-Scores:")
        for k, v in result["sub_scores"].items():
            print(f"    {k:<20}: {v}")

    print(f"{'=' * 60}\n")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Dark Web Credential Intelligence Platform"
    )

    parser.add_argument(
        "--lookup",
        metavar="EMAIL",
        help="Look up risk profile for a specific email"
    )

    args = parser.parse_args()

    if args.lookup:
        lookup_email(args.lookup)
    else:
        run_full_pipeline()