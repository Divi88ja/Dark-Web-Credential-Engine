"""
nlp/entity_extractor.py
------------------------
NLP-based entity extraction from unstructured breach text.

We combine two approaches:
  1. Regex — fast, precise for well-defined patterns (emails, domains)
  2. spaCy — for context-aware extraction from free text

Design decision: We wrap spaCy in a try/except because some environments
may not have the model installed. The pipeline degrades gracefully to
regex-only mode.
"""

import re
import pandas as pd
from typing import List, Dict, Optional
from src.utils.helpers import setup_logger, is_valid_email, load_config

logger = setup_logger(__name__)

# ── Try to load spaCy; fall back gracefully if not available ──
try:
    import spacy
    _NLP = spacy.load("en_core_web_sm")
    SPACY_AVAILABLE = True
    logger.info("spaCy model loaded: en_core_web_sm")
except Exception as e:
    SPACY_AVAILABLE = False
    logger.warning(f"spaCy not available — using regex only. ({e})")
    _NLP = None


# ─────────────────────────────────────────────────────────────
# COMPILED REGEX PATTERNS
# These are compiled once at import time for performance.
# ─────────────────────────────────────────────────────────────

PATTERNS = {
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9\-]+\.)+(?:com|org|net|io|edu|gov|mil|co|in|uk|de|fr)\b"
    ),
    "ipv4": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ),
    "hash_md5": re.compile(
        r"\b[a-fA-F0-9]{32}\b"
    ),
    "hash_sha1": re.compile(
        r"\b[a-fA-F0-9]{40}\b"
    ),
    "hash_sha256": re.compile(
        r"\b[a-fA-F0-9]{64}\b"
    ),
    "url": re.compile(
        r"https?://[^\s\"'>]+"
    ),
}

# ── Keywords that indicate elevated risk or sensitive access ──
SENSITIVE_KEYWORDS = [
    "admin", "administrator", "password", "passwd", "pwd",
    "login", "access", "root", "secret", "api_key", "apikey",
    "token", "vpn", "internal", "corp", "corporate", "employee",
    "staff", "sudo", "privilege", "superuser", "sysadmin",
    "database", "backup", "finance", "payroll", "hr",
]
_KEYWORD_PATTERN = re.compile(
    r"\b(" + "|".join(SENSITIVE_KEYWORDS) + r")\b",
    re.IGNORECASE
)


class EntityExtractor:
    """
    Extract structured entities from breach text.

    Usage:
        extractor = EntityExtractor()
        result = extractor.extract_from_text("admin@acme.com:password123")
        df = extractor.extract_from_dataframe(breach_df)
    """

    def __init__(self, config_path: str = "configs/config.yaml"):
        self.config = load_config(config_path)
        self.sensitive_keywords = self.config["nlp"]["sensitive_keywords"]

    def extract_from_text(self, text: str) -> Dict:
        """
        Extract all entities from a single text string.
        Returns a dict of lists for each entity type.

        Example output:
          {
            "emails": ["admin@acme.com"],
            "domains": ["acme.com"],
            "sensitive_keywords": ["admin", "password"],
            "hash_type": "md5",
            "has_sensitive_keyword": True
          }
        """
        if not text or not isinstance(text, str):
            return self._empty_result()

        result = {
            "emails":               PATTERNS["email"].findall(text.lower()),
            "domains":              PATTERNS["domain"].findall(text.lower()),
            "ipv4_addresses":       PATTERNS["ipv4"].findall(text),
            "urls":                 PATTERNS["url"].findall(text),
            "sensitive_keywords":   _KEYWORD_PATTERN.findall(text.lower()),
            "has_sensitive_keyword": bool(_KEYWORD_PATTERN.search(text)),
            "hash_type":            self._detect_hash_type(text),
        }

        # If spaCy is available, enrich with NER
        if SPACY_AVAILABLE and _NLP:
            result.update(self._spacy_extract(text))

        return result

    def extract_from_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply entity extraction to the full breach DataFrame.
        Adds new columns: has_sensitive_keyword, sensitive_keywords_found, hash_type

        This is called on the cleaned DataFrame before correlation.
        """
        logger.info(f"Running entity extraction on {len(df)} records")

        # Combine all text fields into one string per record for NLP
        df["_combined_text"] = (
            df.get("email", "").fillna("").astype(str) + " " +
            df.get("username", "").fillna("").astype(str) + " " +
            df.get("password_hash", "").fillna("").astype(str)
        )

        # Extract entities from the combined text
        extracted = df["_combined_text"].apply(self.extract_from_text)

        df["has_sensitive_keyword"]   = extracted.apply(lambda x: x["has_sensitive_keyword"])
        df["sensitive_keywords_found"]= extracted.apply(lambda x: ", ".join(set(x["sensitive_keywords"])))
        df["hash_type"]               = extracted.apply(lambda x: x["hash_type"])

        # Drop the temp column
        df.drop(columns=["_combined_text"], inplace=True)

        keyword_count = df["has_sensitive_keyword"].sum()
        logger.info(f"Entity extraction complete. {keyword_count} records with sensitive keywords")
        return df

    def _detect_hash_type(self, text: str) -> str:
        """
        Identify password hash type based on length.
        This matters for risk scoring: plaintext > MD5 > SHA1 > bcrypt.
        """
        parts = text.split(":")
        for part in parts:
            part = part.strip()
            if PATTERNS["hash_sha256"].fullmatch(part):
                return "sha256"
            elif PATTERNS["hash_sha1"].fullmatch(part):
                return "sha1"
            elif PATTERNS["hash_md5"].fullmatch(part):
                return "md5"
            elif len(part) > 0 and not PATTERNS["email"].match(part):
                # Could be plaintext password
                if len(part) < 32 and re.search(r"[a-zA-Z]", part):
                    return "plaintext"
        return "unknown"

    def _spacy_extract(self, text: str) -> Dict:
        """
        Use spaCy NER to extract organizations and persons from free text.
        This helps identify company names mentioned in breach data.
        """
        doc = _NLP(text[:1000])  # cap at 1000 chars for performance
        orgs    = [ent.text for ent in doc.ents if ent.label_ == "ORG"]
        persons = [ent.text for ent in doc.ents if ent.label_ == "PERSON"]
        return {"organizations": orgs, "persons": persons}

    def _empty_result(self) -> Dict:
        return {
            "emails": [], "domains": [], "ipv4_addresses": [],
            "urls": [], "sensitive_keywords": [],
            "has_sensitive_keyword": False, "hash_type": "unknown",
        }

    def get_keyword_stats(self, df: pd.DataFrame) -> Dict:
        """Summarize keyword exposure across the dataset."""
        if "sensitive_keywords_found" not in df.columns:
            return {}
        all_keywords = []
        for kw_str in df["sensitive_keywords_found"].dropna():
            all_keywords.extend([k.strip() for k in kw_str.split(",") if k.strip()])
        from collections import Counter
        return dict(Counter(all_keywords).most_common(10))
