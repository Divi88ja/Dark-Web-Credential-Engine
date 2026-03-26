"""
config/settings.py
------------------
Central configuration for the Dark Web Credential Exposure Correlation Engine.
All tunable parameters live here — no magic numbers scattered in the codebase.
"""

import os
from pathlib import Path

# ─── Project root ───────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parent.parent

# ─── Data paths ─────────────────────────────────────────────────────────────
DATA_DIR        = ROOT_DIR / "data"
RAW_DIR         = DATA_DIR / "raw"
PROCESSED_DIR   = DATA_DIR / "processed"
EMPLOYEE_DIR    = DATA_DIR / "employee"
SIMULATED_DIR   = DATA_DIR / "simulated"

# ─── Model paths ────────────────────────────────────────────────────────────
MODELS_DIR      = ROOT_DIR / "models"
RISK_MODEL_PATH = MODELS_DIR / "risk_scorer.pkl"
SHAP_EXPLAINER_PATH = MODELS_DIR / "shap_explainer.pkl"

# ─── Output paths ───────────────────────────────────────────────────────────
REPORTS_DIR     = ROOT_DIR / "reports"
LOGS_DIR        = ROOT_DIR / "logs"

# ─── Simulation settings ────────────────────────────────────────────────────
SIMULATION = {
    "num_employees": 500,          # Total simulated employees
    "num_breach_records": 2000,    # Total breach dump entries
    "exposure_rate": 0.35,         # 35% of employees appear in breaches
    "company_domain": "acmecorp.com",
    "departments": [
        "Engineering", "Finance", "HR", "Marketing",
        "IT", "Legal", "Sales", "Executive"
    ],
    # Roles and their sensitivity weights (used in risk scoring)
    "role_sensitivity": {
        "CEO": 1.0, "CTO": 1.0, "CFO": 1.0, "CISO": 1.0,
        "Admin": 0.9, "IT Manager": 0.85, "DevOps Engineer": 0.8,
        "Software Engineer": 0.6, "Analyst": 0.5, "Intern": 0.3,
        "Marketing Specialist": 0.4, "HR Specialist": 0.6,
        "Sales Representative": 0.4, "Legal Counsel": 0.75,
    },
    "breach_sources": [
        "LinkedIn2021", "RockYou2024", "Collection#1",
        "Adobe2013", "Dropbox2016", "Yahoo2016",
        "Equifax2017", "TwitterAPI2023"
    ],
}

# ─── Preprocessing settings ─────────────────────────────────────────────────
PREPROCESSING = {
    # Minimum character length for a valid username
    "min_username_length": 3,
    # Regex pattern for valid email addresses
    "email_regex": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    # Keywords that indicate high-sensitivity accounts
    "sensitive_keywords": [
        "admin", "administrator", "root", "sysadmin", "superuser",
        "ceo", "cto", "cfo", "ciso", "director", "manager",
        "password", "passwd", "login", "access", "vpn", "sudo",
    ],
}

# ─── NLP settings ───────────────────────────────────────────────────────────
NLP = {
    "spacy_model": "en_core_web_sm",
    # Entities to extract from unstructured text
    "target_entities": ["ORG", "PERSON", "GPE"],
}

# ─── Correlation engine settings ────────────────────────────────────────────
CORRELATION = {
    # Fuzzy matching threshold (0–100). Lower = more permissive.
    "fuzzy_threshold": 85,
    # If True, domain-only matches (without full email match) are included
    "include_domain_matches": True,
}

# ─── ML Risk Scoring ────────────────────────────────────────────────────────
ML = {
    "test_size": 0.2,
    "random_state": 42,
    "n_estimators": 150,        # Random Forest trees
    "max_depth": 8,
    # Features used for training (order matters for SHAP output)
    "features": [
        "breach_count",
        "unique_sources",
        "password_reuse_score",
        "role_sensitivity",
        "recency_score",
        "exposure_frequency",
        "domain_match_count",
        "sensitive_keyword_hit",
    ],
    # Score thresholds for risk tier classification
    "risk_thresholds": {
        "critical": 80,
        "high": 60,
        "medium": 40,
        "low": 0,
    },
}

# ─── Alert settings ─────────────────────────────────────────────────────────
ALERTS = {
    # Minimum risk score to trigger an alert
    "alert_threshold": 60,
    # Actions mapped to risk tiers
    "actions": {
        "critical": [
            "Force immediate password reset",
            "Suspend account pending security review",
            "Notify CISO and IT Security team",
            "Enable multi-factor authentication",
            "Audit recent login activity",
        ],
        "high": [
            "Require password reset within 24 hours",
            "Enable enhanced login monitoring",
            "Send security awareness notification",
            "Review account permissions",
        ],
        "medium": [
            "Recommend password reset",
            "Send breach notification email",
            "Flag for quarterly security review",
        ],
    },
}

# ─── Dashboard settings ─────────────────────────────────────────────────────
DASHBOARD = {
    "page_title": "Dark Web Credential Monitor",
    "refresh_interval_seconds": 30,
}

# ─── Ensure all directories exist ───────────────────────────────────────────
for d in [RAW_DIR, PROCESSED_DIR, EMPLOYEE_DIR, SIMULATED_DIR,
          MODELS_DIR, REPORTS_DIR, LOGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)
