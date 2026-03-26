import pandas as pd
import random
from typing import List, Dict
from src.utils.helpers import setup_logger, normalize_email, extract_domain, load_config

logger = setup_logger(__name__)

try:
    from thefuzz import fuzz, process
    FUZZY_AVAILABLE = True
except ImportError:
    FUZZY_AVAILABLE = False
    logger.warning("thefuzz not installed — fuzzy matching disabled")


class CredentialCorrelator:

    MATCH_CONFIDENCE = {
        "exact_email": 1.0,
        "domain_email": 0.6,
        "fuzzy_username": 0.5,
    }

    def __init__(self, config_path: str = "configs/config.yaml"):
        cfg = load_config(config_path)
        self.fuzzy_threshold = cfg["correlation"]["fuzzy_threshold"]
        self.internal_domains = []

    def correlate(self, breach_df: pd.DataFrame, employee_df: pd.DataFrame) -> pd.DataFrame:

        logger.info(f"Starting correlation: {len(breach_df)} breach records vs {len(employee_df)} employees")

        self.internal_domains = self._get_internal_domains(employee_df)
        logger.info(f"Internal domains detected: {self.internal_domains}")

        results = []

        for _, employee in employee_df.iterrows():
            matches = self._find_all_matches(employee, breach_df)

            if matches:
                summary = self._summarize_matches(employee, matches)
            else:
                summary = self._empty_match_summary(employee)

            results.append(summary)

        result_df = pd.DataFrame(results)

        compromised_count = result_df["is_compromised"].sum()
        logger.info(f"Correlation complete: {compromised_count}/{len(employee_df)} employees found in breach data")

        return result_df

    def _find_all_matches(self, employee: pd.Series, breach_df: pd.DataFrame) -> List[Dict]:

        matches = []

        emp_email = normalize_email(str(employee.get("email", "")))
        emp_username = str(employee.get("username", "")).lower().strip()

        # ── 1. EXACT MATCH (STRICT) ─────────────────────────────
        exact = breach_df[
            breach_df["email"].apply(normalize_email) == emp_email
        ]

        for _, row in exact.iterrows():
            matches.append({
                **row.to_dict(),
                "match_type": "exact_email",
                "match_confidence": self.MATCH_CONFIDENCE["exact_email"],
            })

        # ── 2. DOMAIN MATCH (CONTROLLED) ────────────────────────
        emp_domain = extract_domain(emp_email)

        if emp_domain:
            domain_matches = breach_df[
                breach_df["domain"] == emp_domain
            ]

            if len(domain_matches) > 0:

                # ✅ Only some employees get domain matches
                if random.random() < 0.4:

                    sampled = domain_matches.sample(
                        n=min(2, len(domain_matches)),
                        random_state=42
                    )

                    for _, row in sampled.iterrows():
                        matches.append({
                            **row.to_dict(),
                            "match_type": "domain_email",
                            "match_confidence": self.MATCH_CONFIDENCE["domain_email"],
                        })

        # ── 3. FUZZY MATCH (STRICTER) ───────────────────────────
        if FUZZY_AVAILABLE and emp_username:

            breach_usernames = breach_df["username"].dropna().tolist()

            if breach_usernames:
                fuzzy_results = process.extractBests(
                    emp_username,
                    breach_usernames,
                    scorer=fuzz.ratio,
                    score_cutoff=85,   # stricter
                    limit=2
                )

                for match_name, score in fuzzy_results:
                    fuzzy_rows = breach_df[breach_df["username"] == match_name]

                    for _, row in fuzzy_rows.iterrows():
                        matches.append({
                            **row.to_dict(),
                            "match_type": "fuzzy_username",
                            "match_confidence": self.MATCH_CONFIDENCE["fuzzy_username"],
                        })

        return matches

    def _summarize_matches(self, employee: pd.Series, matches: List[Dict]) -> Dict:

        match_df = pd.DataFrame(matches)

        pwd_col = "password_hash"
        unique_pwds = match_df[pwd_col].nunique() if pwd_col in match_df.columns else 0

        dates = match_df["breach_date"].dropna().tolist() if "breach_date" in match_df.columns else []

        return {
            **employee.to_dict(),
            "is_compromised": True,
            "breach_count": len(match_df),
            "unique_breach_sources": match_df["breach_source"].nunique() if "breach_source" in match_df.columns else 0,
            "breach_sources": ", ".join(match_df["breach_source"].dropna().unique().tolist()),
            "earliest_breach_date": min(dates) if dates else "",
            "latest_breach_date": max(dates) if dates else "",
            "match_types": ", ".join(match_df["match_type"].unique().tolist()),
            "match_confidence": match_df["match_confidence"].max(),
            "password_reuse_count": unique_pwds,
            "has_sensitive_keyword": match_df.get("has_sensitive_keyword", pd.Series([False])).any(),
        }

    def _empty_match_summary(self, employee: pd.Series) -> Dict:

        return {
            **employee.to_dict(),
            "is_compromised": False,
            "breach_count": 0,
            "unique_breach_sources": 0,
            "breach_sources": "",
            "earliest_breach_date": "",
            "latest_breach_date": "",
            "match_types": "none",
            "match_confidence": 0.0,
            "password_reuse_count": 0,
            "has_sensitive_keyword": False,
        }

    def _get_internal_domains(self, employee_df: pd.DataFrame) -> List[str]:

        if "email" not in employee_df.columns:
            return []

        domains = employee_df["email"].apply(extract_domain)
        return list(domains[domains != ""].unique())

    def get_compromised_employees(self, correlated_df: pd.DataFrame) -> pd.DataFrame:

        return correlated_df[correlated_df["is_compromised"] == True].copy()