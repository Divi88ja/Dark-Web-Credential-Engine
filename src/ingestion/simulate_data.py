"""
src/ingestion/simulate_data.py
------------------------------
Generates realistic synthetic datasets for development and testing.

WHY: We cannot legally use real dark-web breach data. Instead, we simulate:
  1. An internal employee directory (the "victim" organization)
  2. Dark-web breach dump records (the "attacker" dataset)

This is standard practice in cybersecurity research and CTF competitions.
The Faker library creates realistic-looking but entirely fake PII.
"""

import sys
import random
import hashlib
from pathlib import Path
from datetime import datetime, timedelta

import pandas as pd
from faker import Faker

# ── Path setup so we can import config from anywhere ────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from config.settings import EMPLOYEE_DIR, SIMULATED_DIR, SIMULATION
from config.logger import get_logger

logger = get_logger(__name__)
fake = Faker()
random.seed(42)
Faker.seed(42)


# ──────────────────────────────────────────────────────────────────────────────
# EMPLOYEE DIRECTORY GENERATOR
# ──────────────────────────────────────────────────────────────────────────────

def generate_employee_directory() -> pd.DataFrame:
    """
    Creates a realistic internal employee directory.

    Each employee has:
    - employee_id, name, email (company domain), username
    - department, role, role_sensitivity (0–1 weight)
    - account_created_date, is_admin flag
    """
    logger.info(f"Generating {SIMULATION['num_employees']} employee records...")

    records = []
    domain = SIMULATION["company_domain"]
    roles = list(SIMULATION["role_sensitivity"].keys())
    departments = SIMULATION["departments"]

    for i in range(1, SIMULATION["num_employees"] + 1):
        first = fake.first_name()
        last = fake.last_name()
        role = random.choice(roles)
        dept = random.choice(departments)

        # Standard corporate email format: firstname.lastname@company.com
        email = f"{first.lower()}.{last.lower()}@{domain}"
        # Username: first initial + last name (common IT convention)
        username = f"{first[0].lower()}{last.lower()}"
        # Add a numeric suffix to ensure uniqueness
        if random.random() < 0.2:
            username += str(random.randint(1, 99))

        # Account creation: random date in last 8 years
        created = fake.date_between(start_date="-8y", end_date="today")

        records.append({
            "employee_id": f"EMP{i:04d}",
            "first_name": first,
            "last_name": last,
            "email": email,
            "username": username,
            "department": dept,
            "role": role,
            "role_sensitivity": SIMULATION["role_sensitivity"][role],
            "is_admin": 1 if role in ["Admin", "IT Manager", "CEO", "CTO", "CISO"] else 0,
            "account_created": created.strftime("%Y-%m-%d"),
        })

    df = pd.DataFrame(records)

    # Ensure unique emails (add numeric suffix if collision)
    seen = {}
    for idx, row in df.iterrows():
        email = row["email"]
        if email in seen:
            seen[email] += 1
            base, domain_part = email.split("@")
            df.at[idx, "email"] = f"{base}{seen[email]}@{domain_part}"
        else:
            seen[email] = 0

    output_path = EMPLOYEE_DIR / "employees.csv"
    df.to_csv(output_path, index=False)
    logger.info(f"✓ Employee directory saved → {output_path} ({len(df)} records)")
    return df


# ──────────────────────────────────────────────────────────────────────────────
# BREACH DUMP GENERATOR
# ──────────────────────────────────────────────────────────────────────────────

def _fake_password_hash() -> str:
    """Simulates a leaked MD5 or bcrypt-style hash (NOT real credentials)."""
    raw = fake.password(length=random.randint(8, 16))
    # 60% chance it's MD5 (common in old breaches), 40% plaintext (worst case)
    if random.random() < 0.6:
        return hashlib.md5(raw.encode()).hexdigest()
    return raw  # plaintext — simulates poor security practices


def generate_breach_dumps(employee_df: pd.DataFrame) -> pd.DataFrame:
    """
    Creates simulated dark-web breach dump records.

    Strategy:
    - 35% of records come from actual employees (realistic exposure rate)
    - 65% are random internet users (noise — common in real breach dumps)
    - Each record mimics the messy format of real breach databases:
      email:password_hash, or just username:domain, etc.

    Returns a DataFrame of breach records with metadata.
    """
    logger.info(f"Generating {SIMULATION['num_breach_records']} breach records...")

    num_exposed = int(SIMULATION["num_breach_records"] * SIMULATION["exposure_rate"])
    num_noise = SIMULATION["num_breach_records"] - num_exposed

    # Sample employees who will appear in breach dumps
    exposed_employees = employee_df.sample(
        n=min(num_exposed, len(employee_df)),
        replace=True,  # Same employee can appear in multiple breaches
        random_state=42,
    )

    records = []
    breach_sources = SIMULATION["breach_sources"]

    # ── Records linked to real employees ────────────────────────────────────
    for _, emp in exposed_employees.iterrows():
        source = random.choice(breach_sources)
        # Simulate breach date (within last 5 years)
        breach_date = fake.date_between(start_date="-5y", end_date="today")

        # Randomly corrupt some entries to simulate real-world data quality
        email = emp["email"]
        if random.random() < 0.05:
            # Typo in email domain (simulates OCR errors in dump files)
            email = email.replace(".", random.choice(["", ",", " "]), 1)

        records.append({
            "raw_entry": f"{email}:{_fake_password_hash()}",
            "email": email,
            "username": emp["username"],
            "password_hash": _fake_password_hash(),
            "source_breach": source,
            "breach_date": breach_date.strftime("%Y-%m-%d"),
            "is_employee": 1,  # Ground truth label for evaluation
            "matched_employee_id": emp["employee_id"],
        })

    # ── Noise records (random internet users) ───────────────────────────────
    for _ in range(num_noise):
        source = random.choice(breach_sources)
        breach_date = fake.date_between(start_date="-5y", end_date="today")
        email = fake.email()

        records.append({
            "raw_entry": f"{email}:{_fake_password_hash()}",
            "email": email,
            "username": fake.user_name(),
            "password_hash": _fake_password_hash(),
            "source_breach": source,
            "breach_date": breach_date.strftime("%Y-%m-%d"),
            "is_employee": 0,
            "matched_employee_id": None,
        })

    df = pd.DataFrame(records)
    # Shuffle so employee and noise records are interleaved (realistic)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    output_path = SIMULATED_DIR / "breach_dump.csv"
    df.to_csv(output_path, index=False)
    logger.info(f"✓ Breach dump saved → {output_path} ({len(df)} records, {num_exposed} employee hits)")
    return df


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def run():
    logger.info("=" * 60)
    logger.info("STEP 0: Generating Simulated Datasets")
    logger.info("=" * 60)

    employee_df = generate_employee_directory()
    breach_df = generate_breach_dumps(employee_df)

    logger.info(f"\nSummary:")
    logger.info(f"  Employees generated : {len(employee_df)}")
    logger.info(f"  Breach records      : {len(breach_df)}")
    logger.info(f"  Employee hits       : {breach_df['is_employee'].sum()}")
    logger.info(f"  Noise records       : {(breach_df['is_employee'] == 0).sum()}")

    return employee_df, breach_df


if __name__ == "__main__":
    run()
