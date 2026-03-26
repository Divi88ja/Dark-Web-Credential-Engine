"""
pipeline.py
============
End-to-end orchestration for the Dark Web Credential Exposure Engine.

Hybrid ingestion
----------------
use_hibp=True  → Query HIBP (v3) for each employee email and append results
use_hibp=False → Use existing synthetic/ingested breach data only

Fallback
--------
If HIBP is misconfigured or fails at runtime, the pipeline continues using
synthetic breach data (so it never blocks the rest of the analysis).
"""

from __future__ import annotations

import hashlib
import os
import sys
from typing import Any, Optional

import pandas as pd

# Ensure project root is importable regardless of how this is called.
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.ingestion.data_generator import (
    generate_breach_dataset,
    generate_internal_employee_dataset,
)
from src.ingestion.hibp_client import HIBPClientError, build_client_from_config
from src.ingestion.ingestor import BreachDataIngestor
from src.nlp.entity_extractor import EntityExtractor
from src.correlation.correlator import CredentialCorrelator
from src.ml.risk_scorer import RiskScorer
from src.preprocessing.cleaner import BreachDataCleaner
from src.alerts.alert_engine import AlertEngine
from src.utils.helpers import (
    extract_domain,
    ensure_dir,
    load_config,
    save_json,
    setup_logger,
)

logger = setup_logger(__name__, log_file="logs/pipeline.log")


def _mask_email(email: str) -> str:
    """Mask emails when writing to disk (avoid storing full PII)."""
    try:
        email = (email or "").strip().lower()
        if "@" not in email:
            return "***"
        local, domain = email.split("@", 1)
        if not local:
            return f"***@{domain}"
        return f"{local[0]}***@{domain}"
    except Exception:  # noqa: BLE001
        return "***"


def _hibp_item_to_breach_row(employee_email: str, item: dict[str, Any]) -> dict[str, Any]:
    """Convert one HIBP breach item into a row compatible with our breach schema."""
    email_norm = (employee_email or "").strip().lower()
    username = email_norm.split("@", 1)[0] if "@" in email_norm else ""

    breach_name = item.get("breach_name", "Unknown")
    breach_date = item.get("breach_date", "1970-01-01")
    data_classes = item.get("data_classes", []) or []
    severity = item.get("severity", "LOW")

    # Stable placeholder for the unknown password hash.
    # Using a sha256-shaped hex string ensures downstream hash-type detection.
    hash_seed = "|".join([email_norm, breach_name, str(breach_date), ",".join(map(str, data_classes))])
    password_hash = hashlib.sha256(hash_seed.encode("utf-8")).hexdigest()

    return {
        "email": email_norm,
        "username": username,
        "password_hash": password_hash,
        "breach_source": breach_name,
        "breach_date": breach_date,
        "domain": extract_domain(email_norm),
        # Extra fields (safe for the rest of the pipeline; ignored by ML features)
        "data_classes": data_classes,
        "hibp_severity": severity,
    }


def run_pipeline(
    use_simulated_data: bool = True,
    use_hibp: bool = True,
    config_path: str = "configs/config.yaml",
) -> dict[str, Any]:
    """
    Execute the full pipeline end-to-end.

    Returns a dict containing:
      - risk_df
      - alerts
      - dept_summary
      - (plus intermediate DataFrames if useful)
    """
    cfg = load_config(config_path)

    for d in ["data/processed", "data/internal", "models", "reports", "logs"]:
        ensure_dir(d)

    logger.info("=" * 60)
    logger.info("  DARK WEB CREDENTIAL EXPOSURE PIPELINE — START")
    logger.info("=" * 60)

    # ──────────────────────────────────────────
    # STAGE 1: Ingestion
    # ──────────────────────────────────────────
    logger.info("\n[Step 1/6] Data Ingestion")
    hibp_added_rows = 0
    hibp_sources: set[str] = set()
    hibp_used = False

    if use_simulated_data:
        breach_raw = generate_breach_dataset(n_records=500)
        employee_df = generate_internal_employee_dataset(n_employees=100)
    else:
        ingestor = BreachDataIngestor(config_path)
        breach_raw = ingestor.ingest_all_from_directory()
        # For real-data mode, the employee directory is expected to exist.
        employee_df = pd.read_csv("data/internal/employees.csv")

    if use_hibp and cfg.get("hibp", {}).get("enabled", False):
        logger.info("[HIBP] Hybrid ingestion enabled.")
        hibp_client = build_client_from_config(cfg)

        if hibp_client is None:
            logger.warning("[HIBP] Client unavailable (missing api_key or disabled). Using base data only.")
        else:
            employee_emails = (
                employee_df.get("email", pd.Series([], dtype=str))
                .dropna()
                .astype(str)
                .str.strip()
                .str.lower()
            )
            unique_emails = employee_emails[employee_emails != ""].unique().tolist()

            hibp_rows: list[dict[str, Any]] = []
            fatal_hibp_error: Optional[str] = None

            for email in unique_emails:
                try:
                    items = hibp_client.get_breaches_for_email(email)
                except HIBPClientError as exc:
                    fatal_hibp_error = str(exc)
                    logger.error("[HIBP] Fatal error encountered: %s", exc)
                    break
                except Exception as exc:  # noqa: BLE001
                    # Non-fatal per-email failure: skip this email and keep going.
                    logger.warning("[HIBP] Lookup failed for one email: %s", exc)
                    continue

                for item in items:
                    hibp_sources.add(str(item.get("breach_name", "Unknown")))
                    hibp_rows.append(_hibp_item_to_breach_row(email, item))

            if fatal_hibp_error:
                # Requirement: if API fails -> use simulated data.
                # If we started with real ingestion, regenerate synthetic breach data.
                if not use_simulated_data:
                    logger.warning("[HIBP] Falling back to synthetic breach data due to API failure.")
                    breach_raw = generate_breach_dataset(n_records=500)
                hibp_used = False
            else:
                if hibp_rows:
                    hibp_df = pd.DataFrame(hibp_rows)
                    breach_raw = pd.concat([breach_raw, hibp_df], ignore_index=True)
                    hibp_added_rows = len(hibp_rows)
                    hibp_used = True
                    logger.info("[HIBP] Appended %d breach rows.", hibp_added_rows)
                else:
                    hibp_used = False

    # ──────────────────────────────────────────
    # STAGE 2: Cleaning
    # ──────────────────────────────────────────
    logger.info("\n[Step 2/6] Data Cleaning")
    cleaner = BreachDataCleaner(config_path)
    breach_df = cleaner.run(breach_raw)
    employee_df_clean = employee_df  # correlation expects employee columns as-is in this codebase
    logger.info("[Cleaning] %s", cleaner.get_stats())

    # Save cleaned breach data with masked emails.
    breach_save = breach_df.copy()
    if "email" in breach_save.columns:
        breach_save["email"] = breach_save["email"].apply(_mask_email)
    breach_save.to_csv("data/processed/breach_data_clean.csv", index=False)

    # ──────────────────────────────────────────
    # STAGE 3: NLP
    # ──────────────────────────────────────────
    logger.info("\n[Step 3/6] NLP Entity Extraction")
    extractor = EntityExtractor(config_path)
    breach_df = extractor.extract_from_dataframe(breach_df)

    # ──────────────────────────────────────────
    # STAGE 4: Correlation
    # ──────────────────────────────────────────
    logger.info("\n[Step 4/6] Credential Correlation")
    correlator = CredentialCorrelator(config_path)
    correlated_df = correlator.correlate(breach_df, employee_df_clean)
    correlated_save = correlated_df.copy()
    if "email" in correlated_save.columns:
        correlated_save["email"] = correlated_save["email"].apply(_mask_email)
    correlated_save.to_csv("data/processed/correlated_employees.csv", index=False)

    # ──────────────────────────────────────────
    # STAGE 5: ML risk scoring
    # ──────────────────────────────────────────
    logger.info("\n[Step 5/6] ML Risk Scoring")
    scorer = RiskScorer(config_path)
    metrics = scorer.train(correlated_df)
    logger.info("[ML] Training metrics: %s", metrics)
    risk_df = scorer.score(correlated_df)
    scorer.save("models/")

    risk_save = risk_df.copy()
    if "email" in risk_save.columns:
        risk_save["email"] = risk_save["email"].apply(_mask_email)
    risk_save.to_csv("data/processed/risk_scored_employees.csv", index=False)

    # ──────────────────────────────────────────
    # STAGE 6: Alerts
    # ──────────────────────────────────────────
    logger.info("\n[Step 6/6] Alert Generation")
    alert_engine = AlertEngine(config_path)
    alerts = alert_engine.generate_alerts(risk_df)

    # Mask PII emails inside saved alerts.
    for a in alerts:
        try:
            if "employee" in a and "email" in a["employee"]:
                a["employee"]["email"] = _mask_email(a["employee"]["email"])
        except Exception:  # noqa: BLE001
            pass

    alert_engine.save_alerts(alerts)

    dept_summary = alert_engine.get_department_summary(risk_df)
    dept_summary.to_csv("reports/department_summary.csv", index=False)

    # ──────────────────────────────────────────
    # Metadata for dashboard indicator
    # ──────────────────────────────────────────
    data_source_label = "Synthetic / Real (HIBP)" if hibp_used else "Synthetic"
    metadata = {
        "data_source": data_source_label,
        "hibp_used": hibp_used,
        "hibp_records_added": hibp_added_rows,
        "hibp_breach_sources": sorted(hibp_sources),
    }
    save_json(metadata, "data/processed/ingestion_metadata.json")

    logger.info("\n[Pipeline] Complete. Outputs in data/processed/ and reports/")
    return {
        "breach_df": breach_df,
        "employee_df": employee_df,
        "correlated_df": correlated_df,
        "risk_df": risk_df,
        "alerts": alerts,
        "metrics": metrics,
        "dept_summary": dept_summary,
    }


if __name__ == "__main__":
    # Default: demo synthetic mode with HIBP enabled if configured.
    run_pipeline(use_simulated_data=True, use_hibp=True)

