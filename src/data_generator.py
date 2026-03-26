import json
import random
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

DEPARTMENTS = {
    "Engineering":      {"criticality": 0.85},
    "Finance":          {"criticality": 0.95},
    "Executive":        {"criticality": 1.00},
    "HR":               {"criticality": 0.80},
    "Sales":            {"criticality": 0.60},
    "Marketing":        {"criticality": 0.50},
    "IT Security":      {"criticality": 0.90},
    "Legal":            {"criticality": 0.88},
    "Operations":       {"criticality": 0.65},
    "Customer Support": {"criticality": 0.45},
}

ROLE_SENSITIVITY = {
    "CEO": 1.00, "CTO": 0.98, "CFO": 0.97,
    "VP": 0.90, "Director": 0.82, "Senior Manager": 0.75,
    "Manager": 0.68, "Senior Engineer": 0.62, "Engineer": 0.55,
    "Analyst": 0.48, "Associate": 0.40, "Coordinator": 0.35,
    "Intern": 0.20,
}

BREACH_SOURCES = [
    {"name": "LinkedIn2021", "severity": "major"},
    {"name": "RockYou2024", "severity": "critical"},
    {"name": "Adobe2013", "severity": "major"},
    {"name": "Collection1", "severity": "critical"},
    {"name": "Dropbox2012", "severity": "major"},
    {"name": "Canva2019", "severity": "moderate"},
    {"name": "Gravatar2020", "severity": "minor"},
    {"name": "Trello2022", "severity": "minor"},
    {"name": "LastPass2022", "severity": "critical"},
    {"name": "Twitter2022", "severity": "moderate"},
]

FIRST_NAMES = ["Aarav","Priya","Rohan","Sneha","Vikram","Ananya","Karan","Neha"]
LAST_NAMES  = ["Sharma","Patel","Singh","Mehta","Gupta","Shah","Kumar"]


# ─────────────────────────────────────────────
# EMPLOYEE GENERATOR
# ─────────────────────────────────────────────

def generate_employees(n=100, seed=42):
    random.seed(seed)
    employees = []

    for i in range(n):
        first = random.choice(FIRST_NAMES)
        last = random.choice(LAST_NAMES)

        dept = random.choice(list(DEPARTMENTS.keys()))
        role = random.choice(list(ROLE_SENSITIVITY.keys()))

        employees.append({
            "employee_id": f"EMP{i+1:04d}",
            "name": f"{first} {last}",
            "email": f"{first.lower()}.{last.lower()}@company.com",
            "department": dept,
            "role": role,
            "role_sensitivity": ROLE_SENSITIVITY[role],
            "dept_criticality": DEPARTMENTS[dept]["criticality"],
            "account_created": str(datetime.now().date())
        })

    return employees


# ─────────────────────────────────────────────
# FINAL BREACH GENERATOR (REALISTIC)
# ─────────────────────────────────────────────

def generate_breach_records(employees, seed=99):
    random.seed(seed)
    records = []

    for emp in employees:

        # realistic exposure probability
        base_prob = 0.15
        role_factor = emp["role_sensitivity"] * 0.25
        dept_factor = emp["dept_criticality"] * 0.10
        exposure_prob = min(base_prob + role_factor + dept_factor, 0.65)

        # skip non-exposed users
        if random.random() > exposure_prob:
            continue

        # breach count distribution
        breach_count = random.choices(
            [1, 2, 3, 5],
            weights=[50, 30, 15, 5]
        )[0]

        for _ in range(breach_count):

            breach = random.choice(BREACH_SOURCES)

            # realistic email noise
            rand = random.random()
            if rand < 0.6:
                email = emp["email"]  # exact match
            elif rand < 0.8:
                email = emp["email"].replace("@company.com", "@gmail.com")  # partial
            else:
                email = f"user{random.randint(1000,9999)}@gmail.com"  # external

            # recency
            if random.random() < 0.6:
                days_ago = random.randint(30, 365)
            else:
                days_ago = random.randint(365, 1200)

            records.append({
                "employee_id": emp["employee_id"],
                "email": email,
                "breach_source": breach["name"],
                "breach_severity": breach["severity"],
                "days_since": days_ago,
                "plaintext_pw": random.random() < 0.25,
                "password_reuse_count": random.choices(
                    [0, 1, 2, 3],
                    weights=[50, 30, 15, 5]
                )[0]
            })

    return records


# ─────────────────────────────────────────────
# SAVE FUNCTION
# ─────────────────────────────────────────────

def save_datasets():
    base_dir = Path("data")
    base_dir.mkdir(exist_ok=True)

    employees = generate_employees()
    breaches = generate_breach_records(employees)

    with open(base_dir / "employees.json", "w") as f:
        json.dump(employees, f, indent=2)

    with open(base_dir / "breaches.json", "w") as f:
        json.dump(breaches, f, indent=2)

    print("✅ Data generated successfully")
    print(f"Employees: {len(employees)}")
    print(f"Breach records: {len(breaches)}")


if __name__ == "__main__":
    save_datasets()