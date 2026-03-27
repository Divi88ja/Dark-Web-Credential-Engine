import os
import sys
import json
import pandas as pd
import plotly.express as px
import streamlit as st
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────
# ✅ MUST BE FIRST STREAMLIT COMMAND
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="Dark Web Credential Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# ── Ensure project root is on path ───────────
ROOT = Path(__file__).parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ─────────────────────────────────────────────
# COLOR PALETTE
# ─────────────────────────────────────────────
LEVEL_COLORS = {
    "LOW": "#22d68a",
    "MEDIUM": "#f5c518",
    "HIGH": "#ff7b35",
    "CRITICAL": "#ff3b5c",
}

# ─────────────────────────────────────────────
# LOAD DATA
# ─────────────────────────────────────────────
@st.cache_data
def load_data():
    path = ROOT / "data" / "risk_profiles.json"

    if not path.exists():
        st.error("Run pipeline first: python src/main.py")
        st.stop()

    with open(path) as f:
        profiles = json.load(f)

    df = pd.DataFrame(profiles)

    return df

risk_df = load_data()

# ─────────────────────────────────────────────
# HEADER (Improved UI)
# ─────────────────────────────────────────────
col1, col2 = st.columns([6, 1])

with col1:
    st.title("🛡️ Dark Web Credential Exposure Dashboard")
    st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")

with col2:
    st.download_button(
        "📥 Download",
        data=json.dumps(risk_df.to_dict(orient="records"), indent=2),
        file_name="risk_profiles.json",
        mime="application/json"
    )

st.divider()

# ─────────────────────────────────────────────
# KPI SECTION
# ─────────────────────────────────────────────
k1, k2, k3, k4 = st.columns(4)

k1.metric("👥 Total", len(risk_df))
k2.metric("🔓 Exposed", int((risk_df["breach_count"] > 0).sum()))
k3.metric("🔴 Critical", int((risk_df["risk_level"] == "CRITICAL").sum()))
k4.metric("🟠 High", int((risk_df["risk_level"] == "HIGH").sum()))

st.divider()

# ─────────────────────────────────────────────
# CHARTS
# ─────────────────────────────────────────────
col1, col2 = st.columns(2)

with col1:
    st.subheader("📊 Risk Score Distribution")

    fig = px.histogram(
        risk_df,
        x="risk_score",
        color="risk_level",
        color_discrete_map=LEVEL_COLORS
    )

    fig.update_layout(
        bargap=0.2,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)"
    )

    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("🎯 Risk Level Breakdown")

    counts = risk_df["risk_level"].value_counts().reindex(
        ["LOW", "MEDIUM", "HIGH", "CRITICAL"], fill_value=0
    )

    fig2 = px.pie(
        values=counts.values,
        names=counts.index,
        color=counts.index,
        color_discrete_map=LEVEL_COLORS
    )

    st.plotly_chart(fig2, use_container_width=True)

st.divider()

# ─────────────────────────────────────────────
# HIGH RISK TABLE (with highlighting)
# ─────────────────────────────────────────────
st.subheader("⚠️ High Risk Users (score ≥ 70)")

high_df = risk_df[risk_df["risk_score"] >= 70].sort_values(
    "risk_score", ascending=False
)

def highlight_risk(row):
    if row["risk_level"] == "CRITICAL":
        return ["background-color: rgba(255,0,0,0.2)"] * len(row)
    elif row["risk_level"] == "HIGH":
        return ["background-color: rgba(255,165,0,0.15)"] * len(row)
    return [""] * len(row)

st.info("Showing employees with HIGH and CRITICAL risk")

st.dataframe(
    high_df.style.apply(highlight_risk, axis=1),
    use_container_width=True
)

st.divider()

# ─────────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────────
st.caption(
    "🛡️ Dark Web Credential Exposure Intelligence Platform | "
    "Enterprise Security Monitoring | Demo Data"
)