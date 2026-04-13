import json
from datetime import datetime
from pathlib import Path
import pandas as pd

def generate_alerts(df, cfg):
    return df[df.get("risk_label", "LOW") == "HIGH"]

def generate_html_report(df, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    df.to_html(path, index=False)

def save_alerts_csv(df, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)

def get_high_risk_summary(df):
    return {
        "total_high_risk": len(df[df.get("risk_label") == "HIGH"])
    }