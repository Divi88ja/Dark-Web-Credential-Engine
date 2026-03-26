"""
ingestion/data_generator.py
----------------------------
Legally generates simulated dark-web breach datasets for testing.
In a real project you would replace this with:
  - HaveIBeenPwned API (free tier)
  - IntelX public breach search
  - DeHashed API
  - Publicly available breach datasets (e.g. from academic repos)

Design decision: We simulate realistic noise — typos, missing fields,
mixed formats — to make the pipeline robust from day one.
"""

import random
import string
import pandas as pd
from datetime import datetime, timedelta
from src.utils.helpers import setup_logger

logger = setup_logger(__name__)

# ── Fake company domains to simulate a realistic internal org ──
INTERNAL_DOMAINS = ["acme-corp.com", "acme.internal", "acmehq.com"]

# ── External domains that appear in breaches ──
EXTERNAL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "linkedin.com", "facebook.com", "twitter.com", "dropbox.com",
    "adobe.com", "github.com"
]

ALL_DOMAINS = INTERNAL_DOMAINS + EXTERNAL_DOMAINS

# ── Realistic first/last names ──
FIRST_NAMES = ["alice", "bob", "carol", "dave", "eve", "frank", "grace",
               "henry", "iris", "jack", "karen", "leo", "mary", "nick",
               "olivia", "peter", "quinn", "rachel", "steve", "tina"]
LAST_NAMES  = ["smith", "jones", "patel", "nguyen", "garcia", "brown",
               "taylor", "lee", "anderson", "wilson", "martin", "davis"]

# ── Breach source names (mimics real breach naming) ──
BREACH_SOURCES = [
    "LinkedInBreach2021", "AdobeLeaks2019", "RockYou2024",
    "DropboxHack2012", "FacebookLeak2021", "TwitterBreachQ2",
    "Collection1Combo", "AntiPublicCombo", "InternalForumDump"
]


def _random_password(length: int = 10) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%"
    return "".join(random.choices(chars, k=length))


def _random_date(days_back: int = 1825) -> str:
    """Random date within the last N days."""
    delta = random.randint(0, days_back)
    d = datetime.now() - timedelta(days=delta)
    return d.strftime("%Y-%m-%d")


def _inject_noise(value: str, noise_prob: float = 0.08) -> str:
    """
    Randomly corrupt a value to simulate real-world messy breach data.
    Examples: trailing spaces, uppercase mix, extra chars.
    """
    if random.random() < noise_prob:
        choice = random.randint(0, 3)
        if choice == 0:
            return value.upper()
        elif choice == 1:
            return " " + value + " "
        elif choice == 2:
            return value + str(random.randint(0, 9))
        else:
            return value.replace("@", "[@]")  # malformed email marker
    return value


def generate_breach_dataset(n_records: int = 500, seed: int = 42) -> pd.DataFrame:
    """
    Generate a simulated breach dataset with realistic noise.

    Returns a DataFrame with columns:
      email, username, password_hash, breach_source, breach_date, domain

    This is your "dark web dump" substitute for the internship.
    """
    random.seed(seed)
    records = []

    for _ in range(n_records):
        first = random.choice(FIRST_NAMES)
        last  = random.choice(LAST_NAMES)
        domain = random.choice(ALL_DOMAINS)

        # 30% chance: use company domain (these are the dangerous ones)
        if random.random() < 0.30:
            domain = random.choice(INTERNAL_DOMAINS)

        email    = f"{first}.{last}@{domain}"
        username = f"{first}{last}{random.randint(1, 99)}"
        pwd_hash = _random_password()
        source   = random.choice(BREACH_SOURCES)
        date     = _random_date()

        # Inject noise to simulate real messy data
        email    = _inject_noise(email)
        username = _inject_noise(username, noise_prob=0.05)

        records.append({
            "email":         email,
            "username":      username,
            "password_hash": pwd_hash,
            "breach_source": source,
            "breach_date":   date,
            "domain":        domain,
        })

    df = pd.DataFrame(records)
    logger.info(f"Generated {len(df)} simulated breach records")
    return df


def generate_internal_employee_dataset(n_employees: int = 100, seed: int = 99) -> pd.DataFrame:
    """
    Generate a fake internal employee directory.
    This represents what HR/IT would have: the ground truth of your org's accounts.

    Columns: employee_id, full_name, email, username, department, role, account_created
    """
    random.seed(seed)

    DEPARTMENTS = ["Engineering", "Finance", "HR", "Sales", "Operations",
                   "Legal", "IT", "Marketing", "Executive", "Support"]

    # Role sensitivity (higher = more privileged = higher risk weight)
    ROLES = {
        "Intern":           1,
        "Analyst":          2,
        "Engineer":         3,
        "Senior Engineer":  4,
        "Manager":          5,
        "Director":         7,
        "VP":               8,
        "C-Suite":          10,
        "IT Admin":         9,
        "DBA":              9,
    }

    records = []
    for i in range(1, n_employees + 1):
        first  = random.choice(FIRST_NAMES)
        last   = random.choice(LAST_NAMES)
        domain = random.choice(INTERNAL_DOMAINS)
        email  = f"{first}.{last}@{domain}"
        uname  = f"{first}.{last}"
        dept   = random.choice(DEPARTMENTS)
        role   = random.choice(list(ROLES.keys()))
        created = _random_date(days_back=3650)

        records.append({
            "employee_id":        f"EMP{i:04d}",
            "full_name":          f"{first.title()} {last.title()}",
            "email":              email,
            "username":           uname,
            "department":         dept,
            "role":               role,
            "role_sensitivity":   ROLES[role],
            "account_created":    created,
        })

    df = pd.DataFrame(records)
    logger.info(f"Generated {len(df)} internal employee records")
    return df


if __name__ == "__main__":
    # Quick test
    breach_df   = generate_breach_dataset(200)
    internal_df = generate_internal_employee_dataset(50)
    print("\nSample breach records:")
    print(breach_df.head(3).to_string())
    print("\nSample employee records:")
    print(internal_df.head(3).to_string())
