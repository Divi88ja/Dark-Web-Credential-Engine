"""
src/ingestion/data_simulator.py
────────────────────────────────
Generates realistic synthetic datasets for development and testing.

WHY SIMULATE?
  Real dark-web breach data is illegal to possess and redistribute.
  We simulate it using realistic patterns so the pipeline logic is
  100% valid — you only swap in real data at the ingestion step.

WHAT WE GENERATE:
  1. breach_dataset.csv  — simulated leaked credentials (the "dark web" data)
  2. employee_dataset.csv — internal employee records (the "HR" data)
  3. A known overlap so the correlation engine has something to find
"""

import random
import string
import hashlib
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta
from loguru import logger

# ── Seed for reproducibility ──
random.seed(42)
np.random.seed(42)

# ── Realistic data pools ──
FIRST_NAMES = [
    "alice", "bob", "charlie", "diana", "evan", "fiona", "george",
    "helen", "ivan", "julia", "kevin", "laura", "mike", "nancy",
    "oscar", "paula", "quinn", "rachel", "steve", "tina", "uma",
    "victor", "wendy", "xavier", "yasmin", "zoe"
]

LAST_NAMES = [
    "smith", "jones", "patel", "kumar", "williams", "brown", "davis",
    "wilson", "taylor", "anderson", "thomas", "jackson", "white",
    "harris", "martin", "garcia", "rodriguez", "lewis", "lee", "walker"
]

INTERNAL_DOMAINS = ["acmecorp.com", "techfirm.io", "globalbank.net"]

# External domains that appear in breaches (realistic mix)
EXTERNAL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "protonmail.com", "icloud.com"
]

# Breach source names (simulated known public breaches)
BREACH_SOURCES = [
    "LinkedIn2021", "RockYou2024", "Collection1", "AntiPublic",
    "BreachCompilation", "Cit0day", "DataTrade2022", "LeakDB2023"
]

DEPARTMENTS = [
    "Engineering", "Finance", "HR", "Sales", "Marketing",
    "Security", "Operations", "Legal", "Executive", "IT"
]

# Role sensitivity: higher = more critical account
ROLE_SENSITIVITY = {
    "Software Engineer": 3,
    "Senior Engineer": 4,
    "DevOps Engineer": 5,
    "Database Admin": 8,
    "System Administrator": 8,
    "Security Analyst": 7,
    "CISO": 10,
    "CTO": 10,
    "CEO": 10,
    "CFO": 9,
    "Finance Manager": 6,
    "HR Manager": 5,
    "Sales Rep": 2,
    "Marketing Manager": 3,
    "Legal Counsel": 6,
    "IT Support": 4,
    "VP Engineering": 8,
    "Data Scientist": 4,
    "Product Manager": 3,
    "Analyst": 2,
}


def _random_password_hash() -> str:
    """Simulate a password hash (MD5 style, as commonly seen in breaches)."""
    raw = "".join(random.choices(string.ascii_letters + string.digits, k=12))
    return hashlib.md5(raw.encode()).hexdigest()


def _random_date(start_year: int = 2018, end_year: int = 2024) -> str:
    """Random breach date within a realistic range."""
    start = datetime(start_year, 1, 1)
    end = datetime(end_year, 12, 31)
    delta = end - start
    random_day = start + timedelta(days=random.randint(0, delta.days))
    return random_day.strftime("%Y-%m-%d")


def generate_employee_dataset(
    n_employees: int = 200,
    output_path: str = "data/internal/employees.csv"
) -> pd.DataFrame:
    """
    Create a synthetic internal employee directory.

    Columns:
        employee_id, full_name, email, department, role,
        role_sensitivity, is_admin, hire_date
    """
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    records = []

    for i in range(n_employees):
        first = random.choice(FIRST_NAMES)
        last = random.choice(LAST_NAMES)
        domain = random.choice(INTERNAL_DOMAINS)
        # Some employees have firstname.lastname, others just firstnamelastinitial
        pattern = random.choice([
            f"{first}.{last}",
            f"{first}{last[0]}",
            f"{first[0]}{last}",
            f"{first}.{last}{random.randint(1,99)}"
        ])
        email = f"{pattern}@{domain}"
        role = random.choice(list(ROLE_SENSITIVITY.keys()))
        sensitivity = ROLE_SENSITIVITY[role]

        records.append({
            "employee_id": f"EMP{i+1000:04d}",
            "full_name": f"{first.title()} {last.title()}",
            "email": email,
            "department": random.choice(DEPARTMENTS),
            "role": role,
            "role_sensitivity": sensitivity,
            "is_admin": 1 if sensitivity >= 7 else 0,
            "hire_date": _random_date(2010, 2023),
        })

    df = pd.DataFrame(records)
    df.to_csv(output_path, index=False)
    logger.info(f"Generated {n_employees} employee records → {output_path}")
    return df


def generate_breach_dataset(
    n_records: int = 1000,
    employee_df: pd.DataFrame = None,
    overlap_pct: float = 0.25,
    output_path: str = "data/raw/simulated_breach.csv"
) -> pd.DataFrame:
    """
    Create a synthetic breach/leak dataset.

    IMPORTANT DESIGN DECISION:
        We inject 'overlap_pct' fraction of records that are actual
        employee emails so the correlation engine will find real hits.
        Without this, testing would have no matches.

    Columns:
        email, username, password_hash, source_breach, breach_date,
        additional_info, ip_address
    """
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    records = []
    n_overlapping = int(n_records * overlap_pct)
    n_random = n_records - n_overlapping

    # ── Part 1: Inject real employee emails (creates the "exposures") ──
    if employee_df is not None and len(employee_df) > 0:
        sampled = employee_df.sample(
            n=min(n_overlapping, len(employee_df)),
            replace=True
        )
        for _, emp in sampled.iterrows():
            # Some breaches have both email+username; some just one
            include_username = random.random() > 0.3
            records.append({
                "email": emp["email"],
                "username": emp["email"].split("@")[0] if include_username else "",
                "password_hash": _random_password_hash(),
                "source_breach": random.choice(BREACH_SOURCES),
                "breach_date": _random_date(2019, 2024),
                "additional_info": random.choice([
                    "admin panel access", "login credentials",
                    "vpn account", "", "database backup",
                    "ssh key associated", "api access token"
                ]),
                "ip_address": f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}",
            })

    # ── Part 2: Random non-employee records (noise / false positives) ──
    for _ in range(n_random):
        first = random.choice(FIRST_NAMES)
        last = random.choice(LAST_NAMES)
        domain = random.choice(EXTERNAL_DOMAINS + INTERNAL_DOMAINS)

        # Introduce noise: some are malformed
        noise_type = random.choices(
            ["clean", "malformed", "no_at", "extra_spaces"],
            weights=[0.75, 0.1, 0.05, 0.1]
        )[0]

        if noise_type == "clean":
            email = f"{first}.{last}@{domain}"
        elif noise_type == "malformed":
            email = f"{first}{last}#{domain}"   # missing @
        elif noise_type == "no_at":
            email = f"{first}.{last}.{domain}"  # dot instead of @
        else:
            email = f"  {first}.{last}@{domain}  "  # extra spaces

        records.append({
            "email": email,
            "username": f"{first}_{last}{random.randint(1,99)}",
            "password_hash": _random_password_hash(),
            "source_breach": random.choice(BREACH_SOURCES),
            "breach_date": _random_date(2018, 2024),
            "additional_info": random.choice([
                "password", "login", "access", "admin", "",
                "root", "token", "secret", ""
            ]),
            "ip_address": f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}",
        })

    df = pd.DataFrame(records)
    df.to_csv(output_path, index=False)
    logger.info(f"Generated {len(df)} breach records ({n_overlapping} overlapping) → {output_path}")
    return df


def run_simulation(config: dict) -> tuple:
    """
    Entry point: generate both datasets and return them.
    Called from the main pipeline runner.
    """
    logger.info("Starting data simulation...")
    emp_df = generate_employee_dataset(
        n_employees=200,
        output_path=config["paths"]["internal"] + "employees.csv"
    )
    breach_df = generate_breach_dataset(
        n_records=1000,
        employee_df=emp_df,
        overlap_pct=0.25,
        output_path=config["paths"]["raw_breaches"] + "simulated_breach.csv"
    )
    return breach_df, emp_df


if __name__ == "__main__":
    from src.utils.helpers import load_config, setup_logger
    setup_logger()
    cfg = load_config()
    run_simulation(cfg)
