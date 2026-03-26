"""
tests/test_pipeline.py
-----------------------
Unit and integration tests for the pipeline.
Run with: pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
import pandas as pd
from src.utils.helpers import is_valid_email, extract_domain, normalize_email, days_since
from src.ingestion.data_generator import generate_breach_dataset, generate_internal_employee_dataset
from src.preprocessing.cleaner import BreachDataCleaner
from src.nlp.entity_extractor import EntityExtractor
from src.correlation.correlator import CredentialCorrelator
from src.ml.risk_scorer import RiskScorer, engineer_features


# ─────────────────────────────────────────────
# UTILS TESTS
# ─────────────────────────────────────────────

class TestHelpers:
    def test_valid_email(self):
        assert is_valid_email("alice@acme.com") is True
        assert is_valid_email("not-an-email")   is False
        assert is_valid_email("")               is False
        assert is_valid_email("@domain.com")    is False

    def test_extract_domain(self):
        assert extract_domain("alice@acme.com")    == "acme.com"
        assert extract_domain("invalid")           == ""
        assert extract_domain("bob@sub.corp.io")   == "sub.corp.io"

    def test_normalize_email(self):
        assert normalize_email("  ALICE@ACME.COM  ") == "alice@acme.com"

    def test_days_since(self):
        assert days_since("2020-01-01") > 365
        assert days_since("")           == 9999
        assert days_since("garbage")   == 9999


# ─────────────────────────────────────────────
# DATA GENERATOR TESTS
# ─────────────────────────────────────────────

class TestDataGenerator:
    def test_breach_dataset_shape(self):
        df = generate_breach_dataset(n_records=100)
        assert len(df) == 100
        assert "email" in df.columns
        assert "breach_source" in df.columns

    def test_employee_dataset_shape(self):
        df = generate_internal_employee_dataset(n_employees=50)
        assert len(df) == 50
        assert "employee_id" in df.columns
        assert "role_sensitivity" in df.columns

    def test_datasets_have_common_emails(self):
        # There should be some overlap because generator uses internal domains
        breach = generate_breach_dataset(500)
        emp    = generate_internal_employee_dataset(100)
        breach_domains = set(breach["domain"].dropna())
        emp_domains    = {extract_domain(e) for e in emp["email"]}
        assert len(breach_domains & emp_domains) > 0, "No domain overlap — check generator"


# ─────────────────────────────────────────────
# CLEANER TESTS
# ─────────────────────────────────────────────

class TestCleaner:
    def setup_method(self):
        self.cleaner = BreachDataCleaner()
        self.raw_df  = generate_breach_dataset(200)

    def test_run_returns_dataframe(self):
        result = self.cleaner.run(self.raw_df)
        assert isinstance(result, pd.DataFrame)
        assert len(result) > 0

    def test_no_nan_emails_after_clean(self):
        result = self.cleaner.run(self.raw_df)
        # Email column should not have raw 'nan' strings
        assert "nan" not in result["email"].values

    def test_stats_populated(self):
        self.cleaner.run(self.raw_df)
        stats = self.cleaner.get_stats()
        assert "initial_records" in stats
        assert "final_records" in stats


# ─────────────────────────────────────────────
# NLP TESTS
# ─────────────────────────────────────────────

class TestEntityExtractor:
    def setup_method(self):
        self.extractor = EntityExtractor()

    def test_email_extraction(self):
        result = self.extractor.extract_from_text("Contact admin@acme.com for access")
        assert "admin@acme.com" in result["emails"]

    def test_sensitive_keyword_detection(self):
        result = self.extractor.extract_from_text("admin:password123")
        assert result["has_sensitive_keyword"] is True

    def test_hash_detection_md5(self):
        md5 = "5f4dcc3b5aa765d61d8327deb882cf99"
        result = self.extractor.extract_from_text(f"user@test.com:{md5}")
        assert result["hash_type"] == "md5"

    def test_clean_text_no_keywords(self):
        result = self.extractor.extract_from_text("john.doe@gmail.com")
        assert result["has_sensitive_keyword"] is False


# ─────────────────────────────────────────────
# CORRELATOR TESTS
# ─────────────────────────────────────────────

class TestCorrelator:
    def setup_method(self):
        self.cleaner    = BreachDataCleaner()
        self.extractor  = EntityExtractor()
        self.correlator = CredentialCorrelator()

        breach_raw  = generate_breach_dataset(300)
        breach_clean= self.cleaner.run(breach_raw)
        self.breach = self.extractor.extract_from_dataframe(breach_clean)
        self.emp    = generate_internal_employee_dataset(50)

    def test_correlate_returns_all_employees(self):
        result = self.correlator.correlate(self.breach, self.emp)
        assert len(result) == len(self.emp)

    def test_is_compromised_column_exists(self):
        result = self.correlator.correlate(self.breach, self.emp)
        assert "is_compromised" in result.columns

    def test_some_employees_are_compromised(self):
        result = self.correlator.correlate(self.breach, self.emp)
        # With 300 breach records and 50 employees sharing domains, expect overlap
        assert result["is_compromised"].sum() > 0


# ─────────────────────────────────────────────
# RISK SCORER TESTS
# ─────────────────────────────────────────────

class TestRiskScorer:
    def setup_method(self):
        breach   = generate_breach_dataset(300)
        emp      = generate_internal_employee_dataset(60)
        cleaner  = BreachDataCleaner()
        ext      = EntityExtractor()
        corr     = CredentialCorrelator()

        breach_clean = cleaner.run(breach)
        breach_nlp   = ext.extract_from_dataframe(breach_clean)
        self.corr_df = corr.correlate(breach_nlp, emp)
        self.scorer  = RiskScorer()

    def test_feature_engineering(self):
        result = engineer_features(self.corr_df)
        for col in ["breach_count", "role_sensitivity", "leak_recency_days"]:
            assert col in result.columns

    def test_train_returns_metrics(self):
        metrics = self.scorer.train(self.corr_df)
        assert "accuracy" in metrics
        assert "roc_auc" in metrics
        assert 0 <= metrics["accuracy"] <= 1

    def test_score_produces_0_100_range(self):
        self.scorer.train(self.corr_df)
        scored = self.scorer.score(self.corr_df)
        assert scored["risk_score"].between(0, 100).all()

    def test_explain_adds_explanation_column(self):
        self.scorer.train(self.corr_df)
        scored    = self.scorer.score(self.corr_df)
        explained = self.scorer.explain(scored)
        assert "risk_explanation" in explained.columns
        assert explained["risk_explanation"].notna().all()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
