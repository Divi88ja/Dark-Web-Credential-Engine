"""
preprocessing/cleaner.py
-------------------------
Clean, normalize, and validate breach records.

Design decision: Every transformation is a separate method so you can
test each step independently and enable/disable steps via config.
The pipeline uses method chaining: cleaner.run(df) calls all steps.
"""

import re
import pandas as pd
from src.utils.helpers import setup_logger, normalize_email, normalize_username
from src.utils.helpers import is_valid_email, extract_domain, load_config

logger = setup_logger(__name__)


class BreachDataCleaner:
    """
    Full preprocessing pipeline for breach data.
    Input: raw DataFrame from ingestor
    Output: clean, normalized DataFrame ready for NLP + correlation
    """

    def __init__(self, config_path: str = "configs/config.yaml"):
        cfg = load_config(config_path)
        self.min_email_len = cfg["preprocessing"]["min_email_length"]
        self.max_email_len = cfg["preprocessing"]["max_email_length"]
        self.remove_dupes  = cfg["preprocessing"]["remove_duplicates"]
        self.stats = {}

    def run(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Run all cleaning steps in order.
        Returns cleaned DataFrame + stores stats for reporting.
        """
        initial_count = len(df)
        logger.info(f"Starting preprocessing on {initial_count} records")

        df = self._ensure_required_columns(df)
        df = self._normalize_emails(df)
        df = self._normalize_usernames(df)
        df = self._extract_domains(df)
        df = self._remove_malformed(df)
        df = self._remove_duplicates(df)
        df = self._fill_missing_values(df)

        final_count = len(df)
        self.stats = {
            "initial_records": initial_count,
            "final_records":   final_count,
            "removed_records": initial_count - final_count,
            "removal_rate":    f"{(1 - final_count/max(initial_count,1))*100:.1f}%"
        }
        logger.info(f"Preprocessing complete: {initial_count} → {final_count} records")
        return df

    def _ensure_required_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add missing columns with default values so downstream code doesn't break."""
        required = {
            "email":          "",
            "username":       "",
            "password_hash":  "",
            "breach_source":  "unknown",
            "breach_date":    "",
            "domain":         "",
        }
        for col, default in required.items():
            if col not in df.columns:
                df[col] = default
                logger.debug(f"Added missing column: {col}")
        return df

    def _normalize_emails(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Normalize email: lowercase, strip whitespace, remove common obfuscations.
        Example: " John.Doe[@]ACME.COM " → "john.doe@acme.com"
        """
        df["email"] = (
            df["email"]
            .astype(str)
            .str.strip()
            .str.lower()
            # Remove common obfuscations used in breach dumps
            .str.replace(r"\[@\]", "@", regex=True)
            .str.replace(r"\[dot\]", ".", regex=True)
            .str.replace(r"\s+", "", regex=True)       # remove all spaces
        )
        return df

    def _normalize_usernames(self, df: pd.DataFrame) -> pd.DataFrame:
        """Lowercase and strip usernames."""
        df["username"] = df["username"].astype(str).str.strip().str.lower()
        # Store original before heavy normalization for fuzzy matching
        df["username_raw"] = df["username"]
        return df

    def _extract_domains(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract domain from email column.
        This is critical for domain-level correlation (e.g., all @acme-corp.com leaks).
        """
        df["domain_extracted"] = df["email"].apply(extract_domain)
        # If domain column already exists and extracted domain is empty, keep original
        df["domain"] = df.apply(
            lambda r: r["domain_extracted"] if r["domain_extracted"] else r["domain"],
            axis=1
        )
        return df

    def _remove_malformed(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Remove records that are clearly invalid:
        - No email AND no username (we can't correlate anything)
        - Email too short or too long
        - Email is literally 'nan' or 'none'
        """
        invalid_strings = {"nan", "none", "null", "n/a", "", "unknown"}

        # Remove rows with no usable identifier
        mask_no_email    = df["email"].isin(invalid_strings)
        mask_no_username = df["username"].isin(invalid_strings)
        df = df[~(mask_no_email & mask_no_username)].copy()

        # Remove emails that are clearly wrong length
        df = df[
            (df["email"].str.len() >= self.min_email_len) |
            (df["email"].isin(invalid_strings))  # keep if no email but has username
        ].copy()

        # Remove emails that fail format validation (only filter valid-looking ones)
        has_at = df["email"].str.contains("@", na=False)
        valid_email = df["email"].apply(is_valid_email)
        # Keep: valid emails OR records with no email (username-only)
        df = df[valid_email | ~has_at].copy()

        return df

    def _remove_duplicates(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Remove duplicate (email, breach_source) combinations.
        We keep duplicates across different sources — the same email
        appearing in two breaches is meaningful for risk scoring.
        """
        if not self.remove_dupes:
            return df
        before = len(df)
        df = df.drop_duplicates(subset=["email", "breach_source"], keep="first")
        logger.info(f"Removed {before - len(df)} duplicate (email, source) pairs")
        return df

    def _fill_missing_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fill remaining NaN values with sensible defaults."""
        df["breach_source"] = df["breach_source"].fillna("unknown")
        df["breach_date"]   = df["breach_date"].fillna("")
        df["password_hash"] = df["password_hash"].fillna("")
        return df

    def get_stats(self) -> dict:
        return self.stats
