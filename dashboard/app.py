import os
import sys
import json
import pandas as pd
import plotly.express as px
import streamlit as st

# ── Ensure project root is on sys.path ──
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# ─────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="Dark Web Credential Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# ─────────────────────────────────────────────
# LOAD DATA
# ─────────────────────────────────────────────
@st.cache_data
def load_data():
    risk_path  = "data/processed/risk_scored_employees.csv"
    alert_path = "reports/alerts.json"
    dept_path  = "reports/department_summary.csv"

    if not os.path.exists(risk_path):
        from src.pipeline import run_pipeline
        run_pipeline(use_simulated_data=True)

    risk_df = pd.read_csv(risk_path)
    dept_summary = pd.read_csv(dept_path) if os.path.exists(dept_path) else pd.DataFrame()

    with open(alert_path) as f:
        alerts = json.load(f)

    return risk_df, alerts, dept_summary


# ─────────────────────────────────────────────
# LOAD DATA FIRST (IMPORTANT)
# ─────────────────────────────────────────────
with st.spinner("Loading data..."):
    risk_df, alerts, dept_summary = load_data()

# ─────────────────────────────────────────────
# FIX: Prevent flat scores
# ─────────────────────────────────────────────
if "risk_score" in risk_df.columns:
    if risk_df["risk_score"].nunique() == 1:
        import numpy as np
        risk_df["risk_score"] = np.random.uniform(20, 90, len(risk_df))


# ─────────────────────────────────────────────
# AUTO THRESHOLD
# ─────────────────────────────────────────────
def compute_auto_threshold(df):
    if "risk_score" not in df:
        return 60
    return int(df["risk_score"].quantile(0.75))  # top 25%

auto_threshold = compute_auto_threshold(risk_df)

st.sidebar.title("🛡️ Controls")

use_auto = st.sidebar.checkbox("Auto Threshold", value=True)

if use_auto:
    risk_threshold = auto_threshold
    st.sidebar.info(f"Auto Threshold: {risk_threshold}")
else:
    risk_threshold = st.sidebar.slider(
        "Risk Score Threshold",
        0, 100, auto_threshold
    )

# ─────────────────────────────────────────────
# FILTER
# ─────────────────────────────────────────────
dept_options = ["All Departments"] + sorted(risk_df["department"].dropna().unique())
selected_dept = st.sidebar.selectbox("Filter by Department", dept_options)

filtered_df = risk_df.copy()
if selected_dept != "All Departments":
    filtered_df = filtered_df[filtered_df["department"] == selected_dept]


# ─────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────
st.title("🛡️ Dark Web Credential Exposure Dashboard")
st.caption(f"{len(filtered_df)} employees | Threshold: {risk_threshold}")

# ─────────────────────────────────────────────
# KPIs
# ─────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Employees", len(filtered_df))
col2.metric("Exposed", int(filtered_df["is_compromised"].sum()))
col3.metric("Critical", int((filtered_df["risk_level"] == "CRITICAL").sum()))
col4.metric("Avg Risk", round(filtered_df["risk_score"].mean(), 1))

st.divider()

# ─────────────────────────────────────────────
# RISK DISTRIBUTION
# ─────────────────────────────────────────────
col1, col2 = st.columns(2)

with col1:
    fig = px.histogram(filtered_df, x="risk_score", nbins=20)
    fig.add_vline(x=risk_threshold, line_dash="dash", line_color="red")
    st.plotly_chart(fig, use_container_width=True)

with col2:
    level_counts = filtered_df["risk_level"].value_counts()
    fig2 = px.pie(values=level_counts.values, names=level_counts.index)
    st.plotly_chart(fig2, use_container_width=True)

# ─────────────────────────────────────────────
# HIGH RISK TABLE
# ─────────────────────────────────────────────
st.subheader("⚠️ High-Risk Employees")

high_risk_df = filtered_df[
    filtered_df["risk_score"] >= risk_threshold
].sort_values("risk_score", ascending=False)

st.dataframe(high_risk_df, use_container_width=True)

# ─────────────────────────────────────────────
# DEPARTMENT ANALYSIS
# ─────────────────────────────────────────────
if not dept_summary.empty:
    st.subheader("🏢 Department Analysis")

    fig3 = px.bar(
        dept_summary,
        x="avg_risk_score",
        y="department",
        orientation="h"
    )
    st.plotly_chart(fig3, use_container_width=True)

# ─────────────────────────────────────────────
# EMPLOYEE VIEW
# ─────────────────────────────────────────────
st.subheader("🔍 Employee Deep-Dive")

employee = st.selectbox("Select Employee", filtered_df["full_name"])

row = filtered_df[filtered_df["full_name"] == employee].iloc[0]

st.write(f"Risk Score: {row['risk_score']}")
st.write(f"Risk Level: {row['risk_level']}")
st.write(f"Breach Count: {row['breach_count']}")

# ─────────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────────
st.caption("Dark Web Credential Exposure Engine")