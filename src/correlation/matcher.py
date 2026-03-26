"""
src/correlation/matcher.py
───────────────────────────
The Credential Correlation Engine.

This is the core of the system — it answers the question:
"Which of our employees appear in this breach data?"

THREE MATCHING STRATEGIES (in order of confidence):
  1. EXACT MATCH    — email in breach == employee email (100% confidence)
  2. DOMAIN MATCH   — breach email domain == company domain (medium confidence)
                      Catches external email accounts from our employees
  3. FUZZY MATCH    — username similarity via RapidFuzz (catches typos,
                      name variations, alias accounts)

OUTPUT:
  A DataFrame of "hit records" — one row per matched employee,
  with match type, confidence score, and breach details attached.
"""

import pandas as pd
import numpy as np
from loguru import logger
from rapidfuzz import fuzz, process


def exact_match(
    breach_df: pd.DataFrame,
    employee_df: pd.DataFrame
) -> pd.DataFrame:
    """
    Strategy 1: Direct email-to-email join.

    This is the highest-confidence match type.
    An employee's exact corporate email appears in a breach dump.
    """
    logger.info("Running exact email matching...")

    hits = pd.merge(
        breach_df,
        employee_df,
        on="email",
        how="inner",
        suffixes=("_breach", "_employee")
    )

    if len(hits) > 0:
        hits["match_type"] = "EXACT"
        hits["match_confidence"] = 1.0
        logger.info(f"Exact matches found: {len(hits):,}")
    else:
        logger.info("No exact email matches found")

    return hits


def domain_match(
    breach_df: pd.DataFrame,
    employee_df: pd.DataFrame,
    config: dict
) -> pd.DataFrame:
    """
    Strategy 2: Match on email domain.

    Finds breach records from @acmecorp.com that didn't exact-match.
    This catches:
      - Username variations (john.doe vs john_doe)
      - Former employee emails still in old breaches
      - Department/role email aliases

    We exclude emails already found via exact matching to avoid duplicates.
    """
    logger.info("Running domain-based matching...")

    # Get internal domains from employee data
    internal_domains = set(employee_df["domain"].unique())
    weight = config["correlation"]["domain_match_weight"]

    # Find breach records from internal domains
    domain_hits_breach = breach_df[
        breach_df["domain"].isin(internal_domains)
    ].copy()

    if len(domain_hits_breach) == 0:
        logger.info("No domain matches found")
        return pd.DataFrame()

    # For each domain hit in breach, find the most likely employee
    # We join on domain and then apply additional username similarity
    domain_hits = pd.merge(
        domain_hits_breach,
        employee_df,
        on="domain",
        how="inner",
        suffixes=("_breach", "_employee")
    )

    # Filter: only keep if not already an exact match
    exact_emails = set(employee_df["email"].values)
    domain_only = domain_hits[
        ~domain_hits["email_breach"].isin(exact_emails)
    ].copy()

    if len(domain_only) > 0:
        domain_only["match_type"] = "DOMAIN"
        domain_only["match_confidence"] = weight
        # Rename for consistent schema
        domain_only = domain_only.rename(columns={
            "email_breach": "breach_email_found",
            "email_employee": "email"
        })
        logger.info(f"Domain matches found: {len(domain_only):,}")
    else:
        logger.info("No new domain-only matches after excluding exact matches")

    return domain_only


def fuzzy_match(
    breach_df: pd.DataFrame,
    employee_df: pd.DataFrame,
    config: dict
) -> pd.DataFrame:
    """
    Strategy 3: Fuzzy username matching.

    Uses RapidFuzz to compare usernames from breach records
    against employee usernames. Catches:
      - Typos: 'john.smth' vs 'john.smith'
      - Variations: 'jsmith' vs 'johnsmith'
      - Aliases: 'j.doe' vs 'john.doe'

    Only run on same-domain records to reduce false positives.
    computationally expensive: O(breach × employees), so we
    pre-filter to same domain first.
    """
    logger.info("Running fuzzy username matching...")
    threshold = config["correlation"]["fuzzy_threshold"]
    weight = config["correlation"]["fuzzy_match_weight"]

    internal_domains = set(employee_df["domain"].unique())

    # Only compare usernames from internal domains
    internal_breach = breach_df[
        breach_df["domain"].isin(internal_domains)
    ].copy()

    if len(internal_breach) == 0:
        logger.info("No internal-domain breach records for fuzzy matching")
        return pd.DataFrame()

    # Build lookup: {username: employee_row}
    emp_usernames = employee_df["username"].tolist()

    fuzzy_hits = []

    for _, breach_row in internal_breach.iterrows():
        b_username = str(breach_row.get("username", ""))
        b_email = str(breach_row.get("email", ""))

        # Try matching on breach username
        candidates = []
        if b_username:
            match = process.extractOne(
                b_username,
                emp_usernames,
                scorer=fuzz.token_sort_ratio
            )
            if match and match[1] >= threshold:
                candidates.append((match[0], match[1]))

        # Also try matching on the local part of the breach email
        if "@" in b_email:
            b_local = b_email.split("@")[0]
            match2 = process.extractOne(
                b_local,
                emp_usernames,
                scorer=fuzz.token_sort_ratio
            )
            if match2 and match2[1] >= threshold:
                # Take the better match
                if not candidates or match2[1] > candidates[0][1]:
                    candidates = [(match2[0], match2[1])]

        # If we have a match, find the corresponding employee
        for matched_username, score in candidates:
            emp_rows = employee_df[employee_df["username"] == matched_username]
            for _, emp_row in emp_rows.iterrows():
                hit = {**breach_row.to_dict(), **emp_row.to_dict()}
                hit["match_type"] = "FUZZY"
                hit["match_confidence"] = round(score / 100 * weight, 3)
                hit["fuzzy_score"] = score
                fuzzy_hits.append(hit)

    if not fuzzy_hits:
        logger.info("No fuzzy matches above threshold")
        return pd.DataFrame()

    fuzzy_df = pd.DataFrame(fuzzy_hits)
    # Remove rows already caught by exact matching
    exact_emails = set(employee_df["email"].values)
    fuzzy_df = fuzzy_df[~fuzzy_df.get("email", pd.Series()).isin(exact_emails)]

    logger.info(f"Fuzzy matches found: {len(fuzzy_df):,} (threshold: {threshold})")
    return fuzzy_df


def run_correlation_engine(
    breach_df: pd.DataFrame,
    employee_df: pd.DataFrame,
    config: dict
) -> pd.DataFrame:
    """
    Master function: runs all three matching strategies and
    merges results into one unified 'compromised records' table.

    Called by the main pipeline runner.

    Returns a DataFrame with columns:
        email, employee_id, full_name, department, role,
        role_sensitivity, is_admin, match_type, match_confidence,
        source_breach, breach_date, keyword_count, risk_signal, ...
    """
    logger.info("=" * 50)
    logger.info("STARTING CORRELATION ENGINE")
    logger.info("=" * 50)

    results = []

    # ── Run each strategy ──
    exact_hits = exact_match(breach_df, employee_df)
    if len(exact_hits) > 0:
        results.append(exact_hits)

    domain_hits = domain_match(breach_df, employee_df, config)
    if len(domain_hits) > 0:
        results.append(domain_hits)

    fuzzy_hits = fuzzy_match(breach_df, employee_df, config)
    if len(fuzzy_hits) > 0:
        results.append(fuzzy_hits)

    if not results:
        logger.warning("No matches found across all three strategies")
        return pd.DataFrame()

    # ── Combine and deduplicate ──
    combined = pd.concat(results, ignore_index=True)

    # If the same employee was caught by multiple strategies, keep the
    # highest-confidence match (exact > domain > fuzzy)
    priority = {"EXACT": 3, "DOMAIN": 2, "FUZZY": 1}
    if "employee_id" in combined.columns:
        combined["_priority"] = combined["match_type"].map(priority).fillna(0)
        combined = combined.sort_values("_priority", ascending=False)
        combined = combined.drop_duplicates(subset=["employee_id", "source_breach"], keep="first")
        combined = combined.drop(columns=["_priority"])

    logger.success(f"Correlation complete: {len(combined):,} compromised records identified")
    logger.info(f"  → Exact:  {(combined['match_type']=='EXACT').sum()}")
    logger.info(f"  → Domain: {(combined['match_type']=='DOMAIN').sum()}")
    logger.info(f"  → Fuzzy:  {(combined['match_type']=='FUZZY').sum()}")

    return combined.reset_index(drop=True)
