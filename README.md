# Dark Web Credential Exposure Correlation Engine

> An AI-powered system that detects leaked credentials from dark-web breach datasets,
> correlates them with internal employee accounts, assigns explainable risk scores using
> Machine Learning, and generates automated security alerts and dashboard insights.

---

## Project Structure

```
dark_web_credential_engine/
├── configs/
│   └── config.yaml              # Central configuration (all tuneable params)
├── data/
│   ├── raw/                     # Drop breach CSVs/text dumps here
│   ├── processed/               # Pipeline output files (auto-generated)
│   └── internal/                # Employee directory (auto-generated or provide CSV)
├── src/
│   ├── ingestion/
│   │   ├── data_generator.py    # Simulated breach + employee data generator
│   │   └── ingestor.py          # CSV/text file ingestion pipeline
│   ├── preprocessing/
│   │   └── cleaner.py           # Normalization, dedup, malformed-entry removal
│   ├── nlp/
│   │   └── entity_extractor.py  # Regex + spaCy NLP entity extraction
│   ├── correlation/
│   │   └── correlator.py        # Exact / domain / fuzzy credential matching
│   ├── ml/
│   │   └── risk_scorer.py       # Random Forest + SHAP risk scoring engine
│   ├── alerts/
│   │   └── alert_engine.py      # Alert generation + department summary
│   ├── utils/
│   │   └── helpers.py           # Shared utilities (config, logging, validation)
│   └── pipeline.py              # Main orchestrator — runs end-to-end pipeline
├── dashboard/
│   └── app.py                   # Streamlit security dashboard
├── models/
│   ├── risk_model.pkl           # Saved Random Forest model (auto-generated)
│   └── scaler.pkl               # Feature scaler (auto-generated)
├── notebooks/
│   └── exploration.ipynb        # EDA and model experimentation
├── tests/
│   └── test_pipeline.py         # pytest unit + integration tests
├── reports/
│   ├── alerts.json              # Structured alert output
│   ├── alerts.csv               # Flat alert CSV for Excel/SIEM
│   └── department_summary.csv   # Dept-level exposure stats
├── requirements.txt
└── README.md
```

---

## Quick Start

### 1. Install Dependencies

```bash
# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# Install packages
pip install -r requirements.txt

# Download spaCy model (for NLP entity extraction)
python -m spacy download en_core_web_sm
```

### 2. Run the Full Pipeline

```bash
# From the project root directory
python -m src.pipeline
```

This will:
- Generate 500 simulated breach records + 100 fake employees
- Clean and normalize the data
- Run NLP entity extraction
- Correlate breach data against employee accounts
- Train and apply the ML risk scorer
- Generate security alerts
- Save all outputs to `data/processed/` and `reports/`

### 3. Launch the Dashboard

```bash
streamlit run dashboard/app.py
```

Open your browser to `http://localhost:8501`

### 4. Run Tests

```bash
pytest tests/ -v
```

---

## Using Real Breach Data

1. Place breach CSV files in `data/raw/`
2. Your CSV should have columns like: `email`, `username`, `password`, `date`
   (column aliases are handled automatically — see `ingestor.py`)
3. Place your employee CSV at `data/internal/employees.csv`
   Required columns: `employee_id`, `full_name`, `email`, `username`, `department`, `role`, `role_sensitivity`, `account_created`
4. Edit `configs/config.yaml` to set your internal company domains
5. Run: `python -m src.pipeline` with `use_simulated_data=False`

**Recommended free data sources:**
- HaveIBeenPwned API (https://haveibeenpwned.com/API/v3)
- COMB dataset (academic use)
- DeHashed API (paid)

---

## Configuration

All tuneable parameters are in `configs/config.yaml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `ml.risk_threshold` | 60 | Score above which alerts are generated |
| `correlation.fuzzy_threshold` | 85 | Min fuzzy username match score (0-100) |
| `ml.model_type` | random_forest | `random_forest` or `logistic_regression` |
| `preprocessing.remove_duplicates` | true | Dedup same email+source pairs |

---

## ML Risk Features

The model scores each employee on a 0–100 scale using:

| Feature | Description | Weight Direction |
|---------|-------------|-----------------|
| `breach_count` | Times found in breach data | ↑ Higher = more risk |
| `password_reuse_count` | Unique passwords seen | ↑ More = more risk |
| `role_sensitivity` | 1-10 privilege score | ↑ C-Suite/Admin = more risk |
| `leak_recency_days` | Days since latest breach | ↓ Recent = more risk |
| `exposure_frequency` | Breaches per year employed | ↑ Higher = more risk |
| `domain_match_flag` | Found via company email | ↑ Yes = more risk |
| `sensitive_keyword_flag` | admin/password near creds | ↑ Yes = more risk |
| `match_confidence` | How certain the match is | ↑ Exact match = more risk |

---

## Output Files

| File | Description |
|------|-------------|
| `data/processed/breach_data_clean.csv` | Cleaned breach records |
| `data/processed/correlated_employees.csv` | Employees matched to breaches |
| `data/processed/risk_scored_employees.csv` | Final risk scores + explanations |
| `reports/alerts.json` | Structured alerts for SIEM/API |
| `reports/alerts.csv` | Flat CSV for Excel/reporting |
| `reports/department_summary.csv` | Dept-level exposure stats |
| `models/risk_model.pkl` | Saved ML model |
| `logs/pipeline.log` | Full execution log |

---

## Architecture

```
[Breach Data] + [Employee Directory]
        ↓
   Data Ingestion (ingestor.py)
        ↓
   Preprocessing (cleaner.py)       — normalize, dedupe, validate
        ↓
   NLP Extraction (entity_extractor.py)  — regex + spaCy
        ↓
   Correlation Engine (correlator.py)    — exact / domain / fuzzy
        ↓
   ML Risk Scorer (risk_scorer.py)       — Random Forest + SHAP
        ↓
   Alert Engine (alert_engine.py)        — threshold alerts + actions
        ↓
   Dashboard (app.py)                    — Streamlit visualization
```

---

## Security Notes

- This tool is for **authorized security research only**
- Never run against systems you don't have permission to test
- All simulated data is synthetic — no real credentials are included
- Store real breach data encrypted and delete after analysis

---

*Internship Project — Dark Web Credential Exposure Correlation Engine*
