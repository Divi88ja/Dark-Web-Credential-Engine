"""
dashboard_patch.py
==================
Drop-in additions for your existing Streamlit dashboard (dashboard.py).

Add these imports and UI blocks into your existing dashboard file
at the positions indicated by the comments below.
"""

# ============================================================
# 1. ADD TO IMPORTS at the top of dashboard.py
# ============================================================
import streamlit as st
import pandas as pd

# ============================================================
# 2. ADD THIS HELPER FUNCTION anywhere before your render logic
# ============================================================

def render_data_source_badge(data_sources: list[str]) -> None:
    """Render a coloured badge showing active data sources."""
    if not data_sources:
        return

    has_hibp = "hibp" in data_sources
    has_synthetic = "synthetic" in data_sources

    if has_hibp and has_synthetic:
        label = "🔀 Hybrid (HIBP + Synthetic)"
        colour = "#f0a500"
    elif has_hibp:
        label = "🌐 Real-Time (HIBP)"
        colour = "#00c853"
    else:
        label = "🧪 Synthetic Only"
        colour = "#607d8b"

    st.markdown(
        f"""
        <div style="
            display:inline-block;
            background:{colour};
            color:white;
            padding:4px 14px;
            border-radius:12px;
            font-size:0.85rem;
            font-weight:600;
            margin-bottom:12px;
        ">
            Data Source: {label}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_breach_source_table(breach_df: pd.DataFrame) -> None:
    """
    Show a breakdown table of breach names, sources and counts.
    Place this inside any st.expander or st.container.
    """
    if breach_df.empty or "breach_name" not in breach_df.columns:
        st.info("No breach data available.")
        return

    cols_needed = ["breach_name", "source", "severity"]
    available = [c for c in cols_needed if c in breach_df.columns]

    summary = (
        breach_df.groupby(available)
        .size()
        .reset_index(name="record_count")
        .sort_values("record_count", ascending=False)
    )

    # Colour-code source column
    def _source_badge(src: str) -> str:
        colour = "#00c853" if src == "hibp" else "#607d8b"
        return f'<span style="background:{colour};color:white;padding:2px 8px;border-radius:8px;font-size:0.75rem">{src.upper()}</span>'

    summary["source"] = summary["source"].apply(_source_badge)

    st.markdown("#### Breach Source Breakdown")
    st.write(
        summary.to_html(escape=False, index=False),
        unsafe_allow_html=True,
    )


# ============================================================
# 3. USAGE – paste inside your main render function
# ============================================================

def render_dashboard(pipeline_result: dict) -> None:
    """
    Example of how to integrate the new widgets into your dashboard.
    Replace / merge with your existing render logic.
    """
    breach_df: pd.DataFrame = pipeline_result.get("breach_df", pd.DataFrame())
    data_sources: list[str] = pipeline_result.get("data_sources", [])
    risk_summary: dict = pipeline_result.get("risk_summary", {})

    # ── Header ──────────────────────────────────────────────
    st.title("🕵️ Dark Web Credential Monitor")

    # ── Data source badge ────────────────────────────────────
    render_data_source_badge(data_sources)

    # ── KPI row ──────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Records", risk_summary.get("total_records", 0))
    c2.metric("Unique Breaches", risk_summary.get("unique_breaches", 0))
    c3.metric("HIBP Records", risk_summary.get("hibp_records", 0))
    c4.metric("Synthetic Records", risk_summary.get("synthetic_records", 0))

    st.divider()

    # ── Severity breakdown ───────────────────────────────────
    severity_counts = risk_summary.get("severity_counts", {})
    if severity_counts:
        sev_df = pd.DataFrame(
            list(severity_counts.items()), columns=["Severity", "Count"]
        )
        st.bar_chart(sev_df.set_index("Severity"))

    # ── Breach source table ───────────────────────────────────
    with st.expander("📋 Breach Source Details", expanded=True):
        render_breach_source_table(breach_df)

    # ── Raw data ──────────────────────────────────────────────
    with st.expander("🔍 Raw Breach Records"):
        display_cols = [c for c in ["breach_name", "breach_date", "severity", "source", "data_classes"]
                        if c in breach_df.columns]
        st.dataframe(breach_df[display_cols], use_container_width=True)


# ============================================================
# 4. STANDALONE STREAMLIT ENTRYPOINT (for testing this patch)
# ============================================================

if __name__ == "__main__":
    st.set_page_config(page_title="Dark Web Credential Monitor", layout="wide")

    # Simulate a pipeline result for UI testing
    sample_data = {
        "breach_df": pd.DataFrame([
            {"email": "a@example.com", "breach_name": "LinkedIn", "breach_date": "2021-06-01",
             "severity": "high", "source": "hibp", "data_classes": ["Passwords", "Email addresses"]},
            {"email": "b@example.com", "breach_name": "Adobe", "breach_date": "2013-10-04",
             "severity": "medium", "source": "hibp", "data_classes": ["Email addresses", "Usernames"]},
            {"email": "c@example.com", "breach_name": "SyntheticBreach#1", "breach_date": "2023-01-15",
             "severity": "critical", "source": "synthetic", "data_classes": ["Passwords", "Credit cards"]},
        ]),
        "data_sources": ["hibp", "synthetic"],
        "risk_summary": {
            "total_records": 3,
            "unique_breaches": 3,
            "hibp_records": 2,
            "synthetic_records": 1,
            "severity_counts": {"high": 1, "medium": 1, "critical": 1},
        },
        "alerts": [],
    }

    render_dashboard(sample_data)
