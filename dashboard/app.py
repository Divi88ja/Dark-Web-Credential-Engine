"""
dashboard/app.py
================
Dark Web Credential Exposure Intelligence Platform
Streamlit Dashboard — Full Production Version
"""

import os
import sys
import json
import random
import hashlib
from pathlib import Path
from datetime import datetime, timedelta

import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ─────────────────────────────────────────────
# PAGE CONFIG — MUST BE FIRST
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="CredShield | Dark Web Intel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
# CUSTOM CSS
# ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;600;700&display=swap');

/* Base */
html, body, [class*="css"] {
    font-family: 'DM Sans', sans-serif;
}

/* Dark cyber background */
.stApp {
    background: #0a0e1a;
    color: #e2e8f0;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: #0d1220 !important;
    border-right: 1px solid #1e2d45;
}

[data-testid="stSidebar"] .stMarkdown h2 {
    font-family: 'Space Mono', monospace;
    color: #38bdf8;
    font-size: 0.75rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    border-bottom: 1px solid #1e3a5f;
    padding-bottom: 0.5rem;
    margin-bottom: 1rem;
}

/* Metric Cards */
[data-testid="stMetric"] {
    background: linear-gradient(135deg, #0f1929 0%, #0d1f36 100%);
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 1rem 1.2rem;
    position: relative;
    overflow: hidden;
}

[data-testid="stMetric"]::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, #38bdf8, #818cf8);
}

[data-testid="stMetricLabel"] {
    font-family: 'Space Mono', monospace;
    font-size: 0.7rem !important;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: #64748b !important;
}

[data-testid="stMetricValue"] {
    font-family: 'Space Mono', monospace;
    font-size: 1.8rem !important;
    color: #e2e8f0 !important;
    font-weight: 700;
}

/* Tabs */
[data-testid="stTabs"] button {
    font-family: 'Space Mono', monospace;
    font-size: 0.75rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: #64748b;
}

[data-testid="stTabs"] button[aria-selected="true"] {
    color: #38bdf8;
    border-bottom-color: #38bdf8;
}

/* Headings */
h1 {
    font-family: 'Space Mono', monospace !important;
    background: linear-gradient(135deg, #38bdf8, #818cf8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    font-size: 1.6rem !important;
    letter-spacing: -0.02em;
}

h2, h3 {
    font-family: 'Space Mono', monospace !important;
    color: #94a3b8 !important;
    font-size: 0.85rem !important;
    letter-spacing: 0.12em;
    text-transform: uppercase;
}

/* Dividers */
hr {
    border-color: #1e2d45 !important;
    margin: 1rem 0 !important;
}

/* DataFrames */
[data-testid="stDataFrame"] {
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    overflow: hidden;
}

/* Alert badges */
.badge-critical { background:#ff3b5c22; color:#ff3b5c; border:1px solid #ff3b5c55; padding:2px 8px; border-radius:4px; font-family:'Space Mono',monospace; font-size:0.7rem; }
.badge-high { background:#ff7b3522; color:#ff7b35; border:1px solid #ff7b3555; padding:2px 8px; border-radius:4px; font-family:'Space Mono',monospace; font-size:0.7rem; }
.badge-medium { background:#f5c51822; color:#f5c518; border:1px solid #f5c51855; padding:2px 8px; border-radius:4px; font-family:'Space Mono',monospace; font-size:0.7rem; }
.badge-low { background:#22d68a22; color:#22d68a; border:1px solid #22d68a55; padding:2px 8px; border-radius:4px; font-family:'Space Mono',monospace; font-size:0.7rem; }

/* Alert cards */
.alert-card {
    background: linear-gradient(135deg, #0f1929, #0d1f36);
    border: 1px solid #1e3a5f;
    border-radius: 10px;
    padding: 1rem 1.2rem;
    margin-bottom: 0.75rem;
}

.alert-card.critical { border-left: 3px solid #ff3b5c; }
.alert-card.high { border-left: 3px solid #ff7b35; }
.alert-card.medium { border-left: 3px solid #f5c518; }

/* Info boxes */
.info-box {
    background: #0f1929;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 0.8rem 1rem;
    font-family: 'Space Mono', monospace;
    font-size: 0.75rem;
    color: #64748b;
    margin-bottom: 1rem;
}

/* Buttons */
.stButton button {
    background: linear-gradient(135deg, #1e3a5f, #0f2744) !important;
    border: 1px solid #38bdf855 !important;
    color: #38bdf8 !important;
    font-family: 'Space Mono', monospace !important;
    font-size: 0.75rem !important;
    letter-spacing: 0.08em;
    border-radius: 6px !important;
}

.stButton button:hover {
    border-color: #38bdf8 !important;
    box-shadow: 0 0 12px #38bdf833;
}

/* Selectbox / slider labels */
.stSelectbox label, .stSlider label, .stMultiSelect label {
    font-family: 'Space Mono', monospace !important;
    font-size: 0.7rem !important;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: #64748b !important;
}

/* Progress bar */
.stProgress > div > div {
    background: linear-gradient(90deg, #38bdf8, #818cf8) !important;
}

/* Expander */
[data-testid="stExpander"] {
    background: #0f1929;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
}

/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0a0e1a; }
::-webkit-scrollbar-thumb { background: #1e3a5f; border-radius: 3px; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────
LEVEL_COLORS = {
    "LOW": "#22d68a",
    "MEDIUM": "#f5c518",
    "HIGH": "#ff7b35",
    "CRITICAL": "#ff3b5c",
}

PLOTLY_THEME = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font_color="#94a3b8",
    font_family="Space Mono, monospace",
    xaxis=dict(gridcolor="#1e2d45", zerolinecolor="#1e2d45"),
    yaxis=dict(gridcolor="#1e2d45", zerolinecolor="#1e2d45"),
)

# ─────────────────────────────────────────────
# SYNTHETIC DATA GENERATOR (Standalone demo)
# ─────────────────────────────────────────────
@st.cache_data
def generate_demo_data(n=120, seed=42):
    random.seed(seed)
    np.random.seed(seed)

    departments = ["Engineering", "Finance", "HR", "Legal", "Marketing", "Operations", "C-Suite", "IT Security"]
    roles = {
        "Engineering": ["Software Engineer", "DevOps", "QA Engineer"],
        "Finance": ["Financial Analyst", "CFO", "Accountant"],
        "HR": ["HR Manager", "Recruiter", "People Ops"],
        "Legal": ["Legal Counsel", "Compliance Officer"],
        "Marketing": ["Marketing Manager", "Brand Strategist"],
        "Operations": ["Operations Manager", "Logistics"],
        "C-Suite": ["CEO", "CTO", "COO", "CISO"],
        "IT Security": ["Security Analyst", "Pen Tester", "SOC Analyst"],
    }
    breach_sources = ["LinkedIn2021", "Adobe", "RockYou2024", "LastPass", "Twitter", "Facebook", "Dropbox", "Canva", "MyFitnessPal", "Equifax"]
    domains = ["corp.io", "internal.org", "enterprise.net"]

    records = []
    for i in range(n):
        dept = random.choice(departments)
        role = random.choice(roles[dept])
        sensitivity = 9 if dept == "C-Suite" else (7 if dept in ["IT Security", "Finance", "Legal"] else random.randint(1, 6))
        breach_count = np.random.poisson(2 if sensitivity > 6 else 0.8)
        pw_reuse = min(breach_count + random.randint(0, 2), 8)
        recency = random.randint(10, 1200)
        domain_match = random.random() < (0.7 if breach_count > 0 else 0.1)
        keyword_flag = random.random() < 0.3
        match_conf = random.choice([1.0, 0.85, 0.6, 0.0]) if breach_count > 0 else 0.0
        exposure_freq = round(breach_count / max(random.uniform(0.5, 5), 0.1), 2)

        # Risk score (mimics ML output)
        score = (
            breach_count * 10
            + pw_reuse * 5
            + sensitivity * 3
            + (1000 - recency) / 50
            + (domain_match * 8)
            + (keyword_flag * 6)
            + match_conf * 10
            + exposure_freq * 4
        )
        score = min(max(score + random.gauss(0, 3), 0), 100)

        level = (
            "CRITICAL" if score >= 80
            else "HIGH" if score >= 60
            else "MEDIUM" if score >= 40
            else "LOW"
        )

        email_local = f"user{i:03d}"
        domain = random.choice(domains)
        email_hash = hashlib.md5(f"{email_local}@{domain}".encode()).hexdigest()[:6]

        first = random.choice(["Alex","Jordan","Sam","Taylor","Morgan","Casey","Riley","Drew","Avery","Quinn"])
        last = random.choice(["Smith","Chen","Patel","Garcia","Kim","Johnson","Williams","Brown","Lee","Davis"])

        breach_src = random.sample(breach_sources, min(breach_count, len(breach_sources))) if breach_count > 0 else []
        breach_date = (datetime.now() - timedelta(days=recency)).strftime("%Y-%m-%d") if breach_count > 0 else None

        records.append({
            "employee_id": f"EMP{i+100:04d}",
            "name": f"{first} {last}",
            "email_masked": f"{email_local[0]}***@{domain}",
            "department": dept,
            "role": role,
            "role_sensitivity": sensitivity,
            "breach_count": breach_count,
            "password_reuse_count": pw_reuse,
            "leak_recency_days": recency,
            "domain_match_flag": int(domain_match),
            "sensitive_keyword_flag": int(keyword_flag),
            "match_confidence": match_conf,
            "exposure_frequency": exposure_freq,
            "breach_sources": ", ".join(breach_src) if breach_src else "None",
            "latest_breach_date": breach_date,
            "risk_score": round(score, 1),
            "risk_level": level,
        })

    return pd.DataFrame(records)


@st.cache_data
def load_pipeline_data():
    """Try to load real pipeline output; fall back to demo data."""
    ROOT = Path(__file__).parent.parent
    risk_path = ROOT / "data" / "processed" / "risk_scored_employees.csv"
    alerts_path = ROOT / "reports" / "alerts.json"
    dept_path = ROOT / "reports" / "department_summary.csv"
    meta_path = ROOT / "data" / "processed" / "ingestion_metadata.json"

    using_demo = False

    if risk_path.exists():
        risk_df = pd.read_csv(risk_path)
    else:
        risk_df = generate_demo_data()
        using_demo = True

    alerts = []
    if alerts_path.exists():
        with open(alerts_path) as f:
            alerts = json.load(f)

    dept_summary = None
    if dept_path.exists():
        dept_summary = pd.read_csv(dept_path)

    metadata = {}
    if meta_path.exists():
        with open(meta_path) as f:
            metadata = json.load(f)

    return risk_df, alerts, dept_summary, metadata, using_demo


# ─────────────────────────────────────────────
# LOAD DATA
# ─────────────────────────────────────────────
risk_df, alerts, dept_summary, metadata, using_demo = load_pipeline_data()

# Ensure required columns exist
if "risk_level" not in risk_df.columns:
    risk_df["risk_level"] = risk_df["risk_score"].apply(
        lambda s: "CRITICAL" if s >= 80 else "HIGH" if s >= 60 else "MEDIUM" if s >= 40 else "LOW"
    )

# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ CredShield")
    st.markdown('<div class="info-box">DARK WEB INTEL PLATFORM<br/>v2.0 · ' + datetime.now().strftime("%Y-%m-%d") + '</div>', unsafe_allow_html=True)

    if using_demo:
        st.warning("⚡ Demo Mode — Run pipeline to load real data", icon="⚠️")
    else:
        st.success("✅ Live Pipeline Data", icon="✅")
        if metadata.get("hibp_used"):
            st.info(f"🔌 HIBP: {metadata.get('hibp_records_added', 0)} records added")

    st.markdown("## Filters")

    departments = sorted(risk_df["department"].unique()) if "department" in risk_df.columns else []
    sel_depts = st.multiselect("Department", departments, default=departments)

    levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    sel_levels = st.multiselect("Risk Level", levels, default=levels)

    score_range = st.slider("Risk Score Range", 0, 100, (0, 100))

    st.markdown("## Actions")
    if st.button("🔄 Refresh Data"):
        st.cache_data.clear()
        st.rerun()

    st.download_button(
        "📥 Export CSV",
        data=risk_df.to_csv(index=False),
        file_name=f"credential_risk_{datetime.now().strftime('%Y%m%d')}.csv",
        mime="text/csv",
    )

    st.download_button(
        "📥 Export JSON",
        data=json.dumps(risk_df.to_dict(orient="records"), indent=2),
        file_name=f"credential_risk_{datetime.now().strftime('%Y%m%d')}.json",
        mime="application/json",
    )

# ─────────────────────────────────────────────
# FILTER DATA
# ─────────────────────────────────────────────
filtered = risk_df.copy()
if sel_depts and "department" in filtered.columns:
    filtered = filtered[filtered["department"].isin(sel_depts)]
if sel_levels:
    filtered = filtered[filtered["risk_level"].isin(sel_levels)]
filtered = filtered[filtered["risk_score"].between(score_range[0], score_range[1])]

# ─────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────
col_h1, col_h2 = st.columns([5, 1])
with col_h1:
    st.markdown("# 🛡️ Dark Web Credential Exposure Dashboard")
    st.caption(f"Last refreshed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} · {len(filtered):,} records shown")
with col_h2:
    st.markdown("<br/>", unsafe_allow_html=True)

st.divider()

# ─────────────────────────────────────────────
# KPI METRICS
# ─────────────────────────────────────────────
k1, k2, k3, k4, k5, k6 = st.columns(6)

total = len(filtered)
exposed = int((filtered["breach_count"] > 0).sum()) if "breach_count" in filtered.columns else 0
critical_cnt = int((filtered["risk_level"] == "CRITICAL").sum())
high_cnt = int((filtered["risk_level"] == "HIGH").sum())
avg_score = round(filtered["risk_score"].mean(), 1) if len(filtered) else 0
exposure_pct = round(exposed / total * 100, 1) if total else 0

k1.metric("👥 Total Employees", f"{total:,}")
k2.metric("🔓 Exposed", f"{exposed:,}", delta=f"{exposure_pct}%", delta_color="inverse")
k3.metric("🔴 Critical", f"{critical_cnt:,}", delta_color="inverse")
k4.metric("🟠 High Risk", f"{high_cnt:,}", delta_color="inverse")
k5.metric("📊 Avg Risk Score", f"{avg_score}")
k6.metric("✅ Safe", f"{total - exposed:,}", delta_color="normal")

st.divider()

# ─────────────────────────────────────────────
# TABS
# ─────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📊 Overview",
    "🎯 Risk Analysis",
    "🏢 Departments",
    "⚠️ Alerts",
    "🔍 Employee Lookup",
    "🤖 Prediction",
])

# ══════════════════════════════════════════════
# TAB 1: OVERVIEW
# ══════════════════════════════════════════════
with tab1:
    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Risk Score Distribution")
        fig = px.histogram(
            filtered, x="risk_score", color="risk_level",
            color_discrete_map=LEVEL_COLORS,
            nbins=25, barmode="overlay",
            labels={"risk_score": "Risk Score", "risk_level": "Level"},
        )
        fig.update_layout(**PLOTLY_THEME, bargap=0.1, showlegend=True,
                          legend=dict(orientation="h", y=-0.2))
        st.plotly_chart(fig, use_container_width=True, key="chart_1")

    with c2:
        st.subheader("Risk Level Breakdown")
        counts = filtered["risk_level"].value_counts().reindex(
            ["LOW", "MEDIUM", "HIGH", "CRITICAL"], fill_value=0
        )
        fig2 = px.pie(
            values=counts.values, names=counts.index,
            color=counts.index, color_discrete_map=LEVEL_COLORS,
            hole=0.55,
        )
        fig2.update_layout(**PLOTLY_THEME)
        fig2.update_traces(textfont_color="#e2e8f0", textfont_size=11)
        st.plotly_chart(fig2, use_container_width=True, key="chart_2")

    # Breach count trend (simulated timeline)
    st.subheader("Breach Exposure Over Time")
    if "latest_breach_date" in filtered.columns:
        dated = filtered.dropna(subset=["latest_breach_date"]).copy()
        dated["latest_breach_date"] = pd.to_datetime(dated["latest_breach_date"], errors="coerce")
        dated = dated.dropna(subset=["latest_breach_date"])
        if not dated.empty:
            dated["month"] = dated["latest_breach_date"].dt.to_period("M").astype(str)
            timeline = dated.groupby(["month", "risk_level"]).size().reset_index(name="count")
            fig3 = px.bar(timeline, x="month", y="count", color="risk_level",
                          color_discrete_map=LEVEL_COLORS,
                          labels={"month": "Month", "count": "Employees"})
            fig3.update_layout(**PLOTLY_THEME, bargap=0.2)
            st.plotly_chart(fig3, use_container_width=True, key="chart_3")
        else:
            st.info("No breach date data available.")
    else:
        # Simulated timeline
        months = pd.date_range(end=datetime.now(), periods=12, freq="ME").strftime("%Y-%m").tolist()
        sim_data = pd.DataFrame({
            "month": months * 4,
            "risk_level": ["LOW"] * 12 + ["MEDIUM"] * 12 + ["HIGH"] * 12 + ["CRITICAL"] * 12,
            "count": (
                np.random.randint(5, 20, 12).tolist()
                + np.random.randint(3, 12, 12).tolist()
                + np.random.randint(1, 8, 12).tolist()
                + np.random.randint(0, 4, 12).tolist()
            ),
        })
        fig3 = px.bar(sim_data, x="month", y="count", color="risk_level",
                      color_discrete_map=LEVEL_COLORS)
        fig3.update_layout(**PLOTLY_THEME, bargap=0.2)
        st.plotly_chart(fig3, use_container_width=True, key="chart_4")

# ══════════════════════════════════════════════
# TAB 2: RISK ANALYSIS
# ══════════════════════════════════════════════
with tab2:
    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Breach Count vs Risk Score")
        if "breach_count" in filtered.columns:
            fig = px.scatter(
                filtered, x="breach_count", y="risk_score",
                color="risk_level", color_discrete_map=LEVEL_COLORS,
                size="role_sensitivity" if "role_sensitivity" in filtered.columns else None,
                hover_data=["department", "role"] if "department" in filtered.columns else None,
                labels={"breach_count": "Breach Count", "risk_score": "Risk Score"},
            )
            fig.update_layout(**PLOTLY_THEME)
            st.plotly_chart(fig, use_container_width=True, key="chart_5")

    with c2:
        st.subheader("Role Sensitivity vs Risk Score")
        if "role_sensitivity" in filtered.columns:
            fig2 = px.box(
                filtered, x="role_sensitivity", y="risk_score",
                color="risk_level", color_discrete_map=LEVEL_COLORS,
                labels={"role_sensitivity": "Role Sensitivity (1–10)", "risk_score": "Risk Score"},
            )
            fig2.update_layout(**PLOTLY_THEME)
            st.plotly_chart(fig2, use_container_width=True, key="chart_6")

    st.subheader("Feature Importance (ML Risk Factors)")
    features = {
        "Breach Count": 0.28,
        "Password Reuse": 0.22,
        "Role Sensitivity": 0.17,
        "Match Confidence": 0.12,
        "Domain Match Flag": 0.09,
        "Leak Recency": 0.07,
        "Exposure Frequency": 0.03,
        "Keyword Flag": 0.02,
    }
    feat_df = pd.DataFrame(list(features.items()), columns=["Feature", "Importance"])
    feat_df = feat_df.sort_values("Importance")
    fig3 = px.bar(feat_df, x="Importance", y="Feature", orientation="h",
                  color="Importance", color_continuous_scale=["#1e3a5f", "#38bdf8", "#818cf8"])
    fig3.update_layout(**PLOTLY_THEME, coloraxis_showscale=False)
    st.plotly_chart(fig3, use_container_width=True, key="chart_7")

    st.subheader("⚠️ High Risk Employees (Score ≥ 70)")
    high_risk = filtered[filtered["risk_score"] >= 70].sort_values("risk_score", ascending=False)

    def highlight_risk(row):
        if row["risk_level"] == "CRITICAL":
            return ["background-color: rgba(255,59,92,0.12)"] * len(row)
        elif row["risk_level"] == "HIGH":
            return ["background-color: rgba(255,123,53,0.10)"] * len(row)
        return [""] * len(row)

    display_cols = [c for c in ["employee_id", "name", "department", "role", "risk_score", "risk_level", "breach_count", "breach_sources"] if c in high_risk.columns]
    if display_cols:
        st.dataframe(
            high_risk[display_cols].style.apply(highlight_risk, axis=1),
            use_container_width=True, height=350,
        )
    else:
        st.dataframe(high_risk, use_container_width=True, height=350)

# ══════════════════════════════════════════════
# TAB 3: DEPARTMENTS
# ══════════════════════════════════════════════
with tab3:
    if "department" in filtered.columns:
        dept_stats = filtered.groupby("department").agg(
            total=("risk_score", "count"),
            avg_score=("risk_score", "mean"),
            critical=("risk_level", lambda x: (x == "CRITICAL").sum()),
            high=("risk_level", lambda x: (x == "HIGH").sum()),
            exposed=("breach_count", lambda x: (x > 0).sum()) if "breach_count" in filtered.columns else ("risk_score", "count"),
        ).reset_index()
        dept_stats["avg_score"] = dept_stats["avg_score"].round(1)
        dept_stats["exposure_rate"] = (dept_stats["exposed"] / dept_stats["total"] * 100).round(1)

        c1, c2 = st.columns(2)

        with c1:
            st.subheader("Avg Risk Score by Department")
            dept_sorted = dept_stats.sort_values("avg_score", ascending=True)
            fig = px.bar(dept_sorted, x="avg_score", y="department", orientation="h",
                         color="avg_score",
                         color_continuous_scale=["#22d68a", "#f5c518", "#ff7b35", "#ff3b5c"],
                         range_color=[0, 100])
            fig.update_layout(**PLOTLY_THEME, coloraxis_showscale=False)
            st.plotly_chart(fig, use_container_width=True, key="chart_8")

        with c2:
            st.subheader("Critical & High Count by Department")
            fig2 = px.bar(dept_stats, x="department", y=["critical", "high"],
                          barmode="stack",
                          color_discrete_map={"critical": "#ff3b5c", "high": "#ff7b35"})
            fig2.update_layout(**PLOTLY_THEME, bargap=0.3,
                               legend=dict(orientation="h", y=-0.25))
            st.plotly_chart(fig2, use_container_width=True, key="chart_9")

        st.subheader("Department Summary Table")
        st.dataframe(dept_stats.sort_values("avg_score", ascending=False),
                     use_container_width=True)

        # Heatmap
        if "role_sensitivity" in filtered.columns:
            st.subheader("Risk Heatmap: Department × Sensitivity")
            pivot = filtered.pivot_table(
                values="risk_score", index="department",
                columns="risk_level", aggfunc="mean", fill_value=0
            ).reindex(columns=["LOW", "MEDIUM", "HIGH", "CRITICAL"], fill_value=0)
            fig3 = px.imshow(
                pivot,
                color_continuous_scale=["#0f1929", "#1e3a5f", "#ff7b35", "#ff3b5c"],
                aspect="auto", text_auto=".0f",
            )
            fig3.update_layout(**PLOTLY_THEME)
            st.plotly_chart(fig3, use_container_width=True, key="chart_10")
    else:
        st.info("Department data not available in current dataset.")

# ══════════════════════════════════════════════
# TAB 4: ALERTS
# ══════════════════════════════════════════════
with tab4:
    if alerts:
        st.subheader(f"🚨 Security Alerts ({len(alerts)} total)")

        alert_level_filter = st.selectbox("Filter by severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM"])
        filtered_alerts = alerts if alert_level_filter == "ALL" else [
            a for a in alerts if a.get("risk_level", "").upper() == alert_level_filter
        ]

        for alert in filtered_alerts[:50]:
            level = alert.get("risk_level", "MEDIUM").upper()
            css_class = level.lower()
            emp = alert.get("employee", {})
            name = emp.get("full_name") or emp.get("name") or "Unknown"
            dept = emp.get("department", "")
            score = alert.get("risk_score", alert.get("score", "N/A"))
            actions = alert.get("recommended_actions", [])
            timestamp = alert.get("generated_at", "")

            badge = f'<span class="badge-{css_class}">{level}</span>'
            st.markdown(
                f'<div class="alert-card {css_class}">'
                f'<b>{name}</b> · {dept} &nbsp; {badge}<br/>'
                f'<small style="color:#64748b">Risk Score: <b style="color:#e2e8f0">{score}</b>'
                + (f" · {timestamp[:10]}" if timestamp else "") + "</small>"
                + (f"<br/><small style='color:#64748b'>Actions: {' | '.join(actions[:2])}</small>" if actions else "")
                + "</div>",
                unsafe_allow_html=True,
            )

        if len(filtered_alerts) > 50:
            st.caption(f"Showing 50 of {len(filtered_alerts)} alerts.")
    else:
        # Demo alerts from risk data
        st.subheader("🚨 Auto-generated Security Alerts")
        demo_alerts = filtered[filtered["risk_level"].isin(["CRITICAL", "HIGH"])].sort_values("risk_score", ascending=False).head(20)

        if demo_alerts.empty:
            st.success("✅ No high-risk alerts for current filter.")
        else:
            for _, row in demo_alerts.iterrows():
                level = row["risk_level"]
                css_class = level.lower()
                name = row.get("name", row.get("employee_id", "Unknown"))
                dept = row.get("department", "")
                score = row["risk_score"]
                breach_src = row.get("breach_sources", "Unknown")

                badge = f'<span class="badge-{css_class}">{level}</span>'
                st.markdown(
                    f'<div class="alert-card {css_class}">'
                    f'<b>{name}</b> · {dept} &nbsp; {badge}<br/>'
                    f'<small style="color:#64748b">Risk Score: <b style="color:#e2e8f0">{score}</b>'
                    f' · Breaches: {breach_src}</small>'
                    "</div>",
                    unsafe_allow_html=True,
                )

# ══════════════════════════════════════════════
# TAB 5: EMPLOYEE LOOKUP
# ══════════════════════════════════════════════
with tab5:
    st.subheader("🔍 Employee Risk Lookup")

    search_col = "name" if "name" in filtered.columns else ("employee_id" if "employee_id" in filtered.columns else filtered.columns[0])
    search_term = st.text_input(f"Search by {search_col}", placeholder="Type to search...")

    if search_term:
        results = filtered[filtered[search_col].astype(str).str.contains(search_term, case=False, na=False)]
    else:
        results = filtered.sort_values("risk_score", ascending=False).head(20)

    if results.empty:
        st.warning("No employees found matching your search.")
    else:
        for _, row in results.iterrows():
            level = row["risk_level"]
            name = row.get("name", row.get("employee_id", "Unknown"))
            score = row["risk_score"]
            dept = row.get("department", "N/A")
            role = row.get("role", "N/A")

            with st.expander(f"{'🔴' if level=='CRITICAL' else '🟠' if level=='HIGH' else '🟡' if level=='MEDIUM' else '🟢'} {name} · {dept} · Score: {score}"):
                d1, d2, d3 = st.columns(3)
                d1.metric("Risk Score", score)
                d1.metric("Risk Level", level)
                d2.metric("Breach Count", row.get("breach_count", "N/A"))
                d2.metric("PW Reuse", row.get("password_reuse_count", "N/A"))
                d3.metric("Role Sensitivity", row.get("role_sensitivity", "N/A"))
                d3.metric("Match Confidence", row.get("match_confidence", "N/A"))

                info_cols = ["role", "breach_sources", "latest_breach_date", "domain_match_flag", "sensitive_keyword_flag"]
                for col in info_cols:
                    if col in row.index:
                        st.markdown(f"**{col.replace('_',' ').title()}:** `{row[col]}`")

                # Risk gauge
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=score,
                    gauge={
                        "axis": {"range": [0, 100], "tickcolor": "#64748b"},
                        "bar": {"color": LEVEL_COLORS.get(level, "#38bdf8")},
                        "bgcolor": "#0f1929",
                        "steps": [
                            {"range": [0, 40], "color": "rgba(34,214,138,0.13)"},
                            {"range": [40, 60], "color": "rgba(245,197,24,0.13)"},
                            {"range": [60, 80], "color": "rgba(255,123,53,0.13)"},
                            {"range": [80, 100], "color": "rgba(255,59,92,0.13)"},
                        ],
                    },
                    title={"text": "Risk Score", "font": {"color": "#94a3b8", "size": 12}},
                    number={"font": {"color": "#e2e8f0"}},
                ))
                fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", height=220,
                                  margin=dict(t=30, b=10, l=20, r=20))
                st.plotly_chart(fig, use_container_width=True, key="chart_11")

# ══════════════════════════════════════════════
# TAB 6: PREDICTION
# ══════════════════════════════════════════════
with tab6:

    # ── Build / load a lightweight sklearn model from demo data ──
    from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
    from sklearn.preprocessing import LabelEncoder
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, confusion_matrix, classification_report,
    )
    from sklearn.model_selection import train_test_split
    import io

    FEATURE_COLS = [
        "breach_count", "password_reuse_count", "role_sensitivity",
        "leak_recency_days", "domain_match_flag", "sensitive_keyword_flag",
        "match_confidence", "exposure_frequency",
    ]

    @st.cache_resource
    def train_model(df):
        """Train a RandomForest on available data."""
        available = [c for c in FEATURE_COLS if c in df.columns]
        target_col = "risk_level"

        # Fill missing feature columns with 0
        for c in FEATURE_COLS:
            if c not in df.columns:
                df[c] = 0

        X = df[FEATURE_COLS].fillna(0)
        le = LabelEncoder()
        y = le.fit_transform(df[target_col])

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        clf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced")
        clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)
        metrics = {
            "accuracy": round(accuracy_score(y_test, y_pred), 3),
            "precision": round(precision_score(y_test, y_pred, average="weighted", zero_division=0), 3),
            "recall": round(recall_score(y_test, y_pred, average="weighted", zero_division=0), 3),
            "f1": round(f1_score(y_test, y_pred, average="weighted", zero_division=0), 3),
            "cm": confusion_matrix(y_test, y_pred),
            "labels": list(le.classes_),
            "X_test": X_test,
            "y_test": y_test,
            "y_pred": y_pred,
        }

        # Feature importances
        importances = dict(zip(FEATURE_COLS, clf.feature_importances_))

        return clf, le, metrics, importances

    clf_model, label_enc, model_metrics, feat_importances = train_model(risk_df.copy())

    # ── SECTION 1: Live Predictor ──
    st.subheader("🎯 Live Employee Risk Predictor")
    st.caption("Enter employee details below to get an instant ML-based risk prediction.")

    with st.form("prediction_form"):
        fc1, fc2, fc3 = st.columns(3)

        with fc1:
            breach_count     = st.number_input("Breach Count", min_value=0, max_value=20, value=2)
            pw_reuse         = st.number_input("Password Reuse Count", min_value=0, max_value=20, value=1)
            role_sensitivity = st.slider("Role Sensitivity (1=Low, 10=C-Suite)", 1, 10, 5)

        with fc2:
            recency_days     = st.number_input("Leak Recency (days ago)", min_value=0, max_value=3000, value=180)
            exposure_freq    = st.number_input("Exposure Frequency (breaches/year)", min_value=0.0, max_value=10.0, value=0.5, step=0.1)
            match_conf       = st.selectbox("Match Confidence", [0.0, 0.6, 0.85, 1.0], index=1)

        with fc3:
            domain_match     = st.selectbox("Domain Match Flag", [0, 1], format_func=lambda x: "Yes" if x else "No")
            keyword_flag     = st.selectbox("Sensitive Keyword Flag", [0, 1], format_func=lambda x: "Yes" if x else "No")
            st.markdown("<br/>", unsafe_allow_html=True)

        submitted = st.form_submit_button("🔍 Predict Risk", use_container_width=True)

    if submitted:
        input_data = pd.DataFrame([{
            "breach_count": breach_count,
            "password_reuse_count": pw_reuse,
            "role_sensitivity": role_sensitivity,
            "leak_recency_days": recency_days,
            "domain_match_flag": domain_match,
            "sensitive_keyword_flag": keyword_flag,
            "match_confidence": match_conf,
            "exposure_frequency": exposure_freq,
        }])

        pred_encoded = clf_model.predict(input_data)[0]
        pred_proba   = clf_model.predict_proba(input_data)[0]
        pred_label   = label_enc.inverse_transform([pred_encoded])[0]
        confidence   = round(max(pred_proba) * 100, 1)

        # Approximate score
        score_map = {"LOW": 20, "MEDIUM": 50, "HIGH": 70, "CRITICAL": 88}
        approx_score = score_map.get(pred_label, 50)

        color = LEVEL_COLORS.get(pred_label, "#38bdf8")

        st.markdown("---")
        r1, r2, r3, r4 = st.columns(4)
        r1.metric("🎯 Predicted Risk Level", pred_label)
        r2.metric("📊 Approx Risk Score", approx_score)
        r3.metric("✅ Model Confidence", f"{confidence}%")
        r4.metric("🔓 Breach Count", breach_count)

        # Confidence bar per class
        st.markdown("#### Probability Distribution Across Risk Levels")
        proba_df = pd.DataFrame({
            "Risk Level": label_enc.classes_,
            "Probability": [round(p * 100, 1) for p in pred_proba],
        })
        fig_proba = px.bar(
            proba_df, x="Risk Level", y="Probability",
            color="Risk Level", color_discrete_map=LEVEL_COLORS,
            text="Probability",
        )
        fig_proba.update_traces(texttemplate="%{text}%", textposition="outside")
        fig_proba.update_layout(**PLOTLY_THEME, yaxis_range=[0, 110], showlegend=False)
        st.plotly_chart(fig_proba, use_container_width=True, key="chart_12")

        # ── SHAP-style explanation ──
        st.markdown("#### 🧠 SHAP-style Feature Contribution")
        st.caption("Shows how much each feature pushed the risk score up or down.")

        input_vals = input_data.iloc[0]
        base_vals  = risk_df[FEATURE_COLS].fillna(0).mean()
        contribs   = {}
        for feat in FEATURE_COLS:
            diff = float(input_vals[feat]) - float(base_vals[feat])
            contribs[feat] = round(diff * feat_importances.get(feat, 0) * 100, 2)

        contrib_df = pd.DataFrame(
            list(contribs.items()), columns=["Feature", "Contribution"]
        ).sort_values("Contribution")

        contrib_df["Color"] = contrib_df["Contribution"].apply(
            lambda x: "#ff3b5c" if x > 0 else "#22d68a"
        )
        contrib_df["Label"] = contrib_df["Feature"].str.replace("_", " ").str.title()

        fig_shap = px.bar(
            contrib_df, x="Contribution", y="Label", orientation="h",
            color="Color", color_discrete_map="identity",
            labels={"Contribution": "Impact on Risk Score", "Label": "Feature"},
        )
        fig_shap.update_layout(**PLOTLY_THEME, showlegend=False)
        fig_shap.add_vline(x=0, line_color="#64748b", line_width=1)
        st.plotly_chart(fig_shap, use_container_width=True, key="chart_13")

        st.info("🔴 Red bars = factors increasing risk · 🟢 Green bars = factors reducing risk")

    st.divider()

    # ── SECTION 2: Bulk CSV Prediction ──
    st.subheader("📂 Bulk CSV Prediction")
    st.caption("Upload a CSV with employee data to predict risk for multiple employees at once.")

    st.markdown(
        "**Required columns:** `breach_count`, `password_reuse_count`, `role_sensitivity`, "
        "`leak_recency_days`, `domain_match_flag`, `sensitive_keyword_flag`, `match_confidence`, `exposure_frequency`"
    )

    # Sample CSV download
    sample_df = pd.DataFrame([{
        "breach_count": 3, "password_reuse_count": 2, "role_sensitivity": 7,
        "leak_recency_days": 120, "domain_match_flag": 1, "sensitive_keyword_flag": 0,
        "match_confidence": 0.85, "exposure_frequency": 1.2,
    }, {
        "breach_count": 0, "password_reuse_count": 0, "role_sensitivity": 3,
        "leak_recency_days": 800, "domain_match_flag": 0, "sensitive_keyword_flag": 0,
        "match_confidence": 0.0, "exposure_frequency": 0.0,
    }])
    st.download_button(
        "📥 Download Sample CSV Template",
        data=sample_df.to_csv(index=False),
        file_name="sample_employees.csv",
        mime="text/csv",
    )

    uploaded_file = st.file_uploader("Upload Employee CSV", type=["csv"])

    if uploaded_file:
        try:
            upload_df = pd.read_csv(uploaded_file)
            missing = [c for c in FEATURE_COLS if c not in upload_df.columns]
            if missing:
                st.error(f"Missing columns: {', '.join(missing)}")
            else:
                X_bulk = upload_df[FEATURE_COLS].fillna(0)
                preds  = clf_model.predict(X_bulk)
                probas = clf_model.predict_proba(X_bulk)

                upload_df["predicted_risk_level"] = label_enc.inverse_transform(preds)
                upload_df["confidence_%"]         = [round(max(p) * 100, 1) for p in probas]

                st.success(f"✅ Predicted risk for {len(upload_df)} employees!")
                st.dataframe(upload_df, use_container_width=True)

                st.download_button(
                    "📥 Download Predictions CSV",
                    data=upload_df.to_csv(index=False),
                    file_name="bulk_predictions.csv",
                    mime="text/csv",
                )

                # Summary chart
                level_counts = upload_df["predicted_risk_level"].value_counts()
                fig_bulk = px.pie(
                    values=level_counts.values, names=level_counts.index,
                    color=level_counts.index, color_discrete_map=LEVEL_COLORS, hole=0.5,
                    title="Bulk Prediction — Risk Level Distribution",
                )
                fig_bulk.update_layout(**PLOTLY_THEME)
                st.plotly_chart(fig_bulk, use_container_width=True, key="chart_14")

        except Exception as e:
            st.error(f"Error processing file: {e}")

    st.divider()

    # ── SECTION 3: Model Performance Metrics ──
    st.subheader("📈 Model Performance Metrics")
    st.caption("RandomForest classifier trained on current dataset (80/20 train-test split).")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("🎯 Accuracy",  f"{model_metrics['accuracy']*100:.1f}%")
    m2.metric("📏 Precision", f"{model_metrics['precision']*100:.1f}%")
    m3.metric("🔁 Recall",    f"{model_metrics['recall']*100:.1f}%")
    m4.metric("⚖️ F1 Score",  f"{model_metrics['f1']*100:.1f}%")

    mc1, mc2 = st.columns(2)

    with mc1:
        st.markdown("#### Confusion Matrix")
        cm     = model_metrics["cm"]
        labels = model_metrics["labels"]
        fig_cm = px.imshow(
            cm, x=labels, y=labels, text_auto=True,
            color_continuous_scale=["#0f1929", "#1e3a5f", "#38bdf8"],
            labels={"x": "Predicted", "y": "Actual"},
            aspect="auto",
        )
        fig_cm.update_layout(**PLOTLY_THEME, coloraxis_showscale=False)
        st.plotly_chart(fig_cm, use_container_width=True, key="chart_15")

    with mc2:
        st.markdown("#### Feature Importances")
        fi_df = pd.DataFrame(
            list(feat_importances.items()), columns=["Feature", "Importance"]
        ).sort_values("Importance")
        fi_df["Feature"] = fi_df["Feature"].str.replace("_", " ").str.title()

        fig_fi = px.bar(
            fi_df, x="Importance", y="Feature", orientation="h",
            color="Importance",
            color_continuous_scale=["#1e3a5f", "#38bdf8", "#818cf8"],
        )
        fig_fi.update_layout(**PLOTLY_THEME, coloraxis_showscale=False)
        st.plotly_chart(fig_fi, use_container_width=True, key="chart_16")

    # Classification report
    with st.expander("📋 Full Classification Report"):
        report = classification_report(
            model_metrics["y_test"], model_metrics["y_pred"],
            target_names=model_metrics["labels"], output_dict=False
        )
        st.code(report, language="text")

# ─────────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────────
st.divider()
st.markdown(
    '<div style="text-align:center; font-family:Space Mono,monospace; font-size:0.65rem; color:#1e3a5f; padding:1rem;">'
    "🛡️ CREDSHIELD · Dark Web Credential Exposure Intelligence Platform · "
    "Authorized Security Research Only · Demo Data"
    "</div>",
    unsafe_allow_html=True,
)