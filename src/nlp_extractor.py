"""
MODULE: nlp_extractor.py
PURPOSE: Simulates an NLP pipeline that parses raw dark web forum text / paste dumps
         to extract structured entities (emails, IPs, hashes).

PRODUCTION EQUIVALENT:
  - Replace regex with spaCy NER + custom entity ruler for emails/hashes
  - Add BERT-based classifier to determine leak confidence score
  - Feed extracted emails directly into the correlation engine

INTERVIEW TALKING POINT:
  "This module mimics how threat intelligence platforms parse raw paste sites —
   turning noisy unstructured text into actionable indicators of compromise."
"""

import re
import json
from collections import defaultdict
from pathlib import Path


# ─────────────────────────────────────────────
# ENTITY PATTERNS (regex-based NER simulation)
# ─────────────────────────────────────────────

EMAIL_PATTERN    = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
IP_PATTERN       = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
HASH_SHA_PATTERN = re.compile(r"\b[a-fA-F0-9]{40,64}\b")
PASSWORD_PATTERN = re.compile(r"(?:pass|password|passwd|pw)\s*[=:]\s*(\S+)", re.IGNORECASE)


# ─────────────────────────────────────────────
# CORE EXTRACTOR
# ─────────────────────────────────────────────

def extract_entities(text):
    """
    Extract structured entities from a raw unstructured breach text blob.

    Returns:
        dict with keys: emails, ips, md5_hashes, sha_hashes, passwords
    """
    return {
        "emails":     list(set(EMAIL_PATTERN.findall(text))),
        "ips":        list(set(IP_PATTERN.findall(text))),
        "md5_hashes": list(set(HASH_MD5_PATTERN.findall(text))),
        "sha_hashes": list(set(HASH_SHA_PATTERN.findall(text))),
        "passwords":  list(set(PASSWORD_PATTERN.findall(text))),
    }


def classify_leak_confidence(text):
    """
    Heuristic-based confidence classifier for breach data quality.
    In production: replace with a fine-tuned text classifier.

    Scoring logic:
      - Contains plaintext passwords → HIGH
      - Contains hashes + emails    → MEDIUM
      - Contains only emails        → LOW
    """
    has_pw    = bool(PASSWORD_PATTERN.search(text))
    has_hash  = bool(HASH_MD5_PATTERN.search(text) or HASH_SHA_PATTERN.search(text))
    has_email = bool(EMAIL_PATTERN.search(text))

    if has_pw and has_email:
        return "HIGH"
    elif has_hash and has_email:
        return "MEDIUM"
    elif has_email:
        return "LOW"
    return "UNKNOWN"


# ─────────────────────────────────────────────
# PIPELINE INTEGRATION
# ─────────────────────────────────────────────

def process_blob_corpus(blobs, employee_emails):
    """
    Process a list of raw leak text blobs.
    Cross-references extracted emails against known employee email set.

    Returns:
        {
          "total_blobs": int,
          "total_emails_found": int,
          "employee_hits": {email: [blob_indices]},
          "per_blob_results": [...]
        }
    """
    employee_hits    = defaultdict(list)
    per_blob_results = []

    for i, blob in enumerate(blobs):
        entities   = extract_entities(blob)
        confidence = classify_leak_confidence(blob)

        # Cross-reference extracted emails with employee roster
        matched_employees = [e for e in entities["emails"] if e in employee_emails]
        for email in matched_employees:
            employee_hits[email].append(i)

        per_blob_results.append({
            "blob_index":       i,
            "confidence":       confidence,
            "emails_found":     len(entities["emails"]),
            "employee_matches": matched_employees,
            "has_plaintext_pw": bool(entities["passwords"]),
            "has_hashes":       bool(entities["md5_hashes"] or entities["sha_hashes"]),
            "entity_summary":   {k: len(v) for k, v in entities.items()},
        })

    total_emails = sum(r["emails_found"] for r in per_blob_results)

    return {
        "total_blobs":        len(blobs),
        "total_emails_found": total_emails,
        "employee_hits":      dict(employee_hits),
        "per_blob_results":   per_blob_results,
    }


# ─────────────────────────────────────────────
# PIPELINE RUNNER  ←  FIXED: cross-platform path
# ─────────────────────────────────────────────

def run_nlp_pipeline(data_dir=None):
    """
    Entry point: loads blobs + employees, runs NLP extraction, saves results.

    Args:
        data_dir: Path to the data folder.
                  Defaults to <project_root>/data/
                  Works on Windows, Mac, and Linux
                  without any hardcoded paths.
    """
    # ── FIX: resolve path relative to THIS file, not a hardcoded Linux path ──
    if data_dir is None:
        data_dir = str(Path(__file__).parent.parent / "data")

    with open(f"{data_dir}/nlp_leak_blobs.json") as f:
        blobs = json.load(f)

    with open(f"{data_dir}/employees.json") as f:
        employees = json.load(f)

    employee_emails = {e["email"] for e in employees}

    print(f"[NLP] Processing {len(blobs)} leak blobs against {len(employee_emails)} employee emails...")
    results = process_blob_corpus(blobs, employee_emails)

    out_path = f"{data_dir}/nlp_results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=list)

    print(f"[NLP] Employee email hits in unstructured text: {len(results['employee_hits'])}")
    print(f"[NLP] Total emails extracted across all blobs : {results['total_emails_found']}")
    return results


# ─────────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    run_nlp_pipeline()