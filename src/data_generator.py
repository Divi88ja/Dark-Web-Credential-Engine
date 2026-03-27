import random
import json
import os
from datetime import datetime


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
# BREACH DATA GENERATOR
# ─────────────────────────────────────────────

def generate_breach_data(employees, n_records=70):
    severities = ["minor", "moderate", "major", "critical"]
    sources = ["LinkedIn", "Dropbox", "Adobe", "Facebook"]

    breach_data = []

    for _ in range(n_records):
        emp = random.choice(employees)

        breach_data.append({
            "employee_id": emp["employee_id"],
            "email": emp["email"],
            "breach_source": random.choice(sources),
            "breach_severity": random.choice(severities),
            "days_since": random.randint(1, 365),
            "plaintext_pw": random.choice([True, False])
        })

    return breach_data


# ─────────────────────────────────────────────
# NLP BLOBS
# ─────────────────────────────────────────────

def generate_nlp_leak_blobs(employees, n=100):
    blobs = []

    for i in range(n):
        emp = random.choice(employees)  # ✅ use real employees

        password = f"pass{i}{random.randint(100,999)}"

        text = f"Leaked credentials found: email={emp['email']}, password={password}"

        blobs.append({
            "id": i,
            "text": text
        })

    return blobs


# ─────────────────────────────────────────────
# SAVE FUNCTION
# ─────────────────────────────────────────────

def save_datasets():
    os.makedirs("data", exist_ok=True)

    # Employees
    employees = generate_employees()
    with open("data/employees.json", "w") as f:
        json.dump(employees, f, indent=2)

    # Breach data
    breaches = generate_breach_data(employees)
    with open("data/breach_data.json", "w") as f:
        json.dump(breaches, f, indent=2)

    # NLP blobs (REALISTIC NOW)
    blobs = generate_nlp_leak_blobs(employees)
    with open("data/nlp_leak_blobs.json", "w") as f:
        json.dump(blobs, f, indent=2)

    print("✅ Data generated successfully")
    print(f"Employees: {len(employees)}")
    print(f"Breach records: {len(breaches)}")
    print(f"NLP blobs: {len(blobs)}")


# ─────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    save_datasets()