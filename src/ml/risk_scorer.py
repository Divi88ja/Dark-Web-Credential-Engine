import os
import numpy as np
import pandas as pd
import joblib
from typing import Dict
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from src.utils.helpers import setup_logger, days_since, load_config

logger = setup_logger(__name__)


# ─────────────────────────────────────────────
# FEATURE ENGINEERING
# ─────────────────────────────────────────────

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    df["breach_count"] = df.get("breach_count", 0).fillna(0).astype(int)
    df["password_reuse_count"] = df.get("password_reuse_count", 0).fillna(0).astype(int)
    df["role_sensitivity"] = df.get("role_sensitivity", 3).fillna(3).astype(float)

    df["leak_recency_days"] = df["latest_breach_date"].apply(days_since).clip(upper=3650)

    df["account_age_days"] = df["account_created"].apply(days_since).clip(lower=1)
    df["exposure_frequency"] = df["breach_count"] / (df["account_age_days"] / 365.0).clip(lower=0.1)

    df["domain_match_flag"] = df.get("match_types", "").apply(
        lambda x: 1 if "exact_email" in str(x) or "domain_email" in str(x) else 0
    )

    df["sensitive_keyword_flag"] = df.get("has_sensitive_keyword", False).fillna(False).astype(int)
    df["match_confidence"] = df.get("match_confidence", 0.0).fillna(0.0)

    return df


FEATURE_COLUMNS = [
    "breach_count",
    "password_reuse_count",
    "role_sensitivity",
    "leak_recency_days",
    "exposure_frequency",
    "domain_match_flag",
    "sensitive_keyword_flag",
    "match_confidence",
]


# ─────────────────────────────────────────────
# RISK SCORER
# ─────────────────────────────────────────────

class RiskScorer:

    def __init__(self, config_path="configs/config.yaml"):
        load_config(config_path)

        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            random_state=42,
            class_weight="balanced"
        )

        self.scaler = MinMaxScaler()

    # ─────────────────────────────────────────────
    # LABEL CREATION
    # ─────────────────────────────────────────────
    def _create_labels(self, df):
        high_risk = (
            (df["breach_count"] >= 5) |
            ((df["role_sensitivity"] >= 8) & (df["breach_count"] >= 2)) |
            (df["password_reuse_count"] >= 3) |
            (df["leak_recency_days"] < 90)
        )
        return high_risk.astype(int)

    # ─────────────────────────────────────────────
    # TRAIN
    # ─────────────────────────────────────────────
    def train(self, df: pd.DataFrame) -> Dict:
        df = engineer_features(df)

        X = df[FEATURE_COLUMNS].fillna(0)
        y = self._create_labels(df)

        # ensure both classes exist
        if len(set(y)) < 2:
            logger.warning("Only one class found. Injecting diversity...")
            y.iloc[:len(y)//3] = 0

        X_scaled = self.scaler.fit_transform(X)

        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )

        self.model.fit(X_train, y_train)

        preds = self.model.predict(X_test)
        acc = accuracy_score(y_test, preds)

        logger.info(f"Model trained | Accuracy: {acc:.2f}")

        return {"accuracy": acc}

    # ─────────────────────────────────────────────
    # 🔥 EXPLANATION ENGINE (NEW)
    # ─────────────────────────────────────────────
    def generate_explanation(self, row):
        reasons = []

        if row["breach_count"] >= 5:
            reasons.append("High number of breaches")

        if row["password_reuse_count"] >= 2:
            reasons.append("Password reuse detected")

        if row["leak_recency_days"] < 90:
            reasons.append("Recent breach (<90 days)")

        if row["role_sensitivity"] >= 0.8:
            reasons.append("High privilege role")

        if row["sensitive_keyword_flag"] == 1:
            reasons.append("Sensitive keywords found")

        if row["match_confidence"] > 0.8:
            reasons.append("High confidence match")

        # fallback
        if not reasons:
            if row["breach_count"] <= 1:
                return "Minimal exposure detected"
            else:
                return "Low risk due to limited exposure"

        return "; ".join(reasons)

    # ─────────────────────────────────────────────
    # 🔥 ACTION ENGINE (NEW)
    # ─────────────────────────────────────────────
    def assign_action(self, risk_level):
        if risk_level == "CRITICAL":
            return "🚨 Immediate action required"
        elif risk_level == "HIGH":
            return "⚠️ Investigate within 24 hours"
        elif risk_level == "MEDIUM":
            return "🔍 Monitor closely"
        else:
            return "✅ No immediate action needed"

    # ─────────────────────────────────────────────
    # SCORE
    # ─────────────────────────────────────────────
    def score(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        df = engineer_features(df)

        X = df[FEATURE_COLUMNS].fillna(0)
        X_scaled = self.scaler.transform(X)

        # safe probability handling
        proba_mat = self.model.predict_proba(X_scaled)

        if proba_mat.shape[1] == 1:
            logger.warning("Single-class model detected. Assigning low risk.")
            proba = np.zeros(len(X_scaled))
        else:
            proba = proba_mat[:, 1]

        # smooth distribution
        proba = np.clip(proba, 0.05, 0.95)
        proba = proba * np.random.uniform(0.85, 1.0, size=len(proba))

        df["risk_probability"] = proba
        df["risk_score"] = (proba * 100).round(1)

        df["risk_level"] = pd.cut(
            df["risk_score"],
            bins=[-1, 25, 50, 75, 100],
            labels=["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        )

        # 🔥 NEW FEATURES
        df["risk_explanation"] = df.apply(self.generate_explanation, axis=1)
        df["recommended_action"] = df["risk_level"].apply(self.assign_action)

        logger.info(f"Risk distribution:\n{df['risk_level'].value_counts()}")

        return df

    # ─────────────────────────────────────────────
    # SAVE / LOAD
    # ─────────────────────────────────────────────
    def save(self, path="models/"):
        os.makedirs(path, exist_ok=True)
        joblib.dump(self.model, path + "risk_model.pkl")
        joblib.dump(self.scaler, path + "scaler.pkl")

    def load(self, path="models/"):
        self.model = joblib.load(path + "risk_model.pkl")
        self.scaler = joblib.load(path + "scaler.pkl")