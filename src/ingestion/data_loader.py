"""
src/ingestion/data_loader.py
-----------------------------
Handles loading and initial validation of breach datasets.

Design principle: FAIL LOUD on schema issues, WARN SOFTLY on data quality
issues. This prevents silent corruption of downstream pipeline stages.
"""

import sys
import pandas as pd
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from config.settings import SIMULATED_DIR, EMPLOYEE_DIR, RAW_DIR
from config.logger import get_logger

logger = get_logger(__name__)


# ── Required columns for each dataset type ───────────────────────────────────
BREACH_REQUIRED_COLS = {"email", "username", "source_breach", "breach_date"}
EMPLOYEE_REQUIRED_COLS = {"employee_id", "email", "username", "department", "role"}


def load_breach_data(path: Optional[Path] = None) -> pd.DataFrame:
    """
    Loads breach dump CSV. Falls back to simulated data if no path provided.

    In production, you would point this to your ingested breach files
    (e.g., from a dark-web monitoring API or OSINT tool like Dehashed).

    Args:
        path: Optional path to a specific breach CSV file.

    Returns:
        DataFrame with raw breach records.
    """
    if path is None:
        path = SIMULATED_DIR / "breach_dump.csv"

    logger.info(f"Loading breach data from: {path}")

    if not path.exists():
        raise FileNotFoundError(
            f"Breach file not found at {path}. "
            "Run src/ingestion/simulate_data.py first."
        )

    df = pd.read_csv(path, low_memory=False)
    _validate_schema(df, BREACH_REQUIRED_COLS, "breach dump")

    logger.info(f"  Loaded {len(df):,} breach records from {df['source_breach'].nunique()} sources")
    _log_data_quality(df)

    return df


def load_employee_data(path: Optional[Path] = None) -> pd.DataFrame:
    """
    Loads internal employee directory.

    In production, this would come from:
    - Active Directory / LDAP export
    - HR system API (Workday, BambooHR)
    - Identity provider (Okta, Azure AD)

    Args:
        path: Optional path to employee CSV.

    Returns:
        DataFrame with employee records.
    """
    if path is None:
        path = EMPLOYEE_DIR / "employees.csv"

    logger.info(f"Loading employee data from: {path}")

    if not path.exists():
        raise FileNotFoundError(
            f"Employee file not found at {path}. "
            "Run src/ingestion/simulate_data.py first."
        )

    df = pd.read_csv(path, low_memory=False)
    _validate_schema(df, EMPLOYEE_REQUIRED_COLS, "employee directory")

    logger.info(f"  Loaded {len(df):,} employees across {df['department'].nunique()} departments")
    return df


def load_raw_breach_file(path: Path, delimiter: str = ":") -> pd.DataFrame:
    """
    Handles raw unstructured breach dump text files (e.g., email:password format).

    Real breach dumps often look like:
        user@example.com:Password123
        admin@corp.com:$2y$10$abc...
        john.doe@company.com:password

    This parser extracts structured fields from that format.

    Args:
        path: Path to raw dump file (.txt or .csv)
        delimiter: Field separator (default ":")

    Returns:
        DataFrame with extracted fields.
    """
    logger.info(f"Parsing raw breach file: {path}")

    records = []
    skipped = 0

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(delimiter, maxsplit=1)
            if len(parts) < 2:
                skipped += 1
                continue

            email_or_user, password_hash = parts[0].strip(), parts[1].strip()
            records.append({
                "raw_entry": line,
                "email": email_or_user if "@" in email_or_user else None,
                "username": email_or_user.split("@")[0] if "@" in email_or_user else email_or_user,
                "password_hash": password_hash,
                "source_breach": path.stem,
                "breach_date": None,  # Often unknown in raw dumps
            })

    if skipped > 0:
        logger.warning(f"  Skipped {skipped:,} malformed lines (missing delimiter)")

    df = pd.DataFrame(records)
    logger.info(f"  Parsed {len(df):,} records from raw file")
    return df


# ── Internal helpers ──────────────────────────────────────────────────────────

def _validate_schema(df: pd.DataFrame, required_cols: set, dataset_name: str):
    """Raises immediately if required columns are missing — fail loud."""
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(
            f"Schema validation FAILED for '{dataset_name}'. "
            f"Missing columns: {missing}. Found: {set(df.columns)}"
        )
    logger.info(f"  Schema validation PASSED for {dataset_name}")


def _log_data_quality(df: pd.DataFrame):
    """Logs data quality statistics without modifying the DataFrame."""
    null_counts = df.isnull().sum()
    total = len(df)

    for col, nulls in null_counts.items():
        if nulls > 0:
            pct = (nulls / total) * 100
            level = logger.warning if pct > 10 else logger.info
            level(f"  Column '{col}': {nulls:,} nulls ({pct:.1f}%)")
