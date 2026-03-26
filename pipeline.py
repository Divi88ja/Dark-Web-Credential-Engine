import click
import pandas as pd
from pathlib import Path
from loguru import logger
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from src.utils.helpers import load_config, setup_logger, ensure_dir
from src.ingestion.data_simulator import run_simulation
from src.ingestion.ingestor import ingest_all_breach_files, load_employee_file
from src.preprocessing.cleaner import (
    clean_breach_data,
    clean_employee_data,
    compute_breach_frequency,
    save_processed,
)
from src.nlp.entity_extractor import enrich_breach_dataframe
from src.correlation.matcher import run_correlation_engine
from src.ml.risk_scorer import (
    engineer_features,
    train_risk_model,
    compute_risk_scores,
    generate_shap_explanations,
    save_model,
    load_model,   # ✅ added
)
from src.alerts.alert_engine import (
    generate_alerts,
    generate_html_report,
    save_alerts_csv,
    get_high_risk_summary,
)

console = Console()


def print_pipeline_banner():
    console.print(Panel.fit(
        "[bold red]Dark Web Credential Exposure Engine[/bold red]\n"
        "[dim]v1.0.0 | Security Intelligence Pipeline[/dim]",
        border_style="red"
    ))


def print_stage(n: int, name: str):
    console.print(f"\n[bold cyan]▶ Stage {n}: {name}[/bold cyan]")


def print_results_table(scored_df: pd.DataFrame):
    table = Table(
        title="🚨 Top 10 High-Risk Employees",
        box=box.ROUNDED,
        border_style="red"
    )
    table.add_column("Rank", style="dim", width=5)
    table.add_column("Employee", style="bold white")
    table.add_column("Email", style="cyan")
    table.add_column("Department")
    table.add_column("Risk Score", justify="right")
    table.add_column("Risk Level")
    table.add_column("Match Type")

    top10 = scored_df.nlargest(10, "risk_score")
    for i, (_, row) in enumerate(top10.iterrows(), 1):
        label = str(row.get("risk_label", "LOW"))
        color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(label, "white")
        table.add_row(
            str(i),
            str(row.get("full_name", ""))[:25],
            str(row.get("email", ""))[:35],
            str(row.get("department", ""))[:15],
            f"{row.get('risk_score', 0):.1f}",
            f"[{color}]{label}[/{color}]",
            str(row.get("match_type", "")),
        )

    console.print(table)


@click.command()
@click.option("--config", default="config/settings.yaml", help="Path to config YAML")
@click.option("--skip-simulate", is_flag=True, help="Skip data simulation")
@click.option("--no-dashboard", is_flag=True, help="Skip launching dashboard")
def run_pipeline(config: str, skip_simulate: bool, no_dashboard: bool):

    print_pipeline_banner()

    # ──────────────────────────────────────────
    # STAGE 0: Config
    # ──────────────────────────────────────────
    print_stage(0, "Loading Configuration")
    cfg = load_config(config)
    setup_logger(cfg["project"]["log_level"])

    for path_key in ["raw_breaches", "processed", "internal", "models", "reports"]:
        ensure_dir(cfg["paths"][path_key])

    # ──────────────────────────────────────────
    # STAGE 1: Ingestion
    # ──────────────────────────────────────────
    print_stage(1, "Data Ingestion")

    if not skip_simulate:
        console.print("[yellow]Generating simulated data...[/yellow]")
        run_simulation(cfg)

    breach_raw = ingest_all_breach_files(cfg)
    employee_raw = load_employee_file(cfg)

    if len(breach_raw) == 0:
        console.print("[red]ERROR: No breach data loaded[/red]")
        return

    console.print(f"[green]✓[/green] Breach records: {len(breach_raw):,}")
    console.print(f"[green]✓[/green] Employees: {len(employee_raw):,}")

    # ──────────────────────────────────────────
    # STAGE 2: Cleaning
    # ──────────────────────────────────────────
    print_stage(2, "Data Cleaning")

    breach_clean, breach_rejected = clean_breach_data(breach_raw, cfg)
    employee_clean = clean_employee_data(employee_raw)

    breach_freq = compute_breach_frequency(breach_clean)

    save_processed(breach_clean, "breach_clean.csv", cfg)
    save_processed(employee_clean, "employees_clean.csv", cfg)

    # ──────────────────────────────────────────
    # STAGE 3: NLP
    # ──────────────────────────────────────────
    print_stage(3, "NLP Extraction")

    known_domains = set(employee_clean["domain"].unique())
    breach_enriched = enrich_breach_dataframe(breach_clean, known_domains)

    save_processed(breach_enriched, "breach_enriched.csv", cfg)

    # ──────────────────────────────────────────
    # STAGE 4: Correlation
    # ──────────────────────────────────────────
    print_stage(4, "Correlation")

    correlated = run_correlation_engine(breach_enriched, employee_clean, cfg)

    if len(correlated) == 0:
        console.print("[yellow]No exposures found[/yellow]")
        return

    save_processed(correlated, "correlated_hits.csv", cfg)

    # ──────────────────────────────────────────
    # STAGE 5: ML Scoring
    # ──────────────────────────────────────────
    print_stage(5, "Risk Scoring")

    featured_df = engineer_features(correlated, breach_freq)

    # ✅ FIX: load model instead of always training
    if cfg["ml"].get("train_model", False):
        model, scaler, _, _, feature_names = train_risk_model(featured_df, cfg)
        save_model(model, feature_names, cfg["paths"]["models"])
    else:
        model, scaler, feature_names = load_model(cfg["paths"]["models"])

    scored_df = compute_risk_scores(featured_df, model, scaler, feature_names, cfg)
    scored_df = generate_shap_explanations(scored_df, model, feature_names)

    save_processed(scored_df, "scored_employees.csv", cfg)

    print_results_table(scored_df)

    # ──────────────────────────────────────────
    # STAGE 6: Alerts
    # ──────────────────────────────────────────
    print_stage(6, "Alert Generation")

    alerts_df = generate_alerts(scored_df, cfg)

    if len(alerts_df) > 0:
        generate_html_report(alerts_df, cfg["paths"]["reports"] + "alert_report.html")
        save_alerts_csv(alerts_df, cfg["paths"]["reports"] + "alerts.csv")

    # ✅ Insight (important)
    console.print(
        "\n[bold yellow]Insight:[/bold yellow] "
        "High-risk exposure is concentrated in privileged roles and recent breaches."
    )

    # ──────────────────────────────────────────
    # FINAL SUMMARY
    # ──────────────────────────────────────────
    total_employees = len(employee_clean)
    compromised = len(correlated)
    high_risk = len(scored_df[scored_df["risk_label"] == "HIGH"])
    medium_risk = len(scored_df[scored_df["risk_label"] == "MEDIUM"])

    console.print("\n[bold green]📊 FINAL SUMMARY[/bold green]")
    console.print(f"Total Employees        : {total_employees}")
    console.print(f"Compromised Accounts   : {compromised}")
    console.print(f"High Risk Employees    : {high_risk}")
    console.print(f"Medium Risk Employees  : {medium_risk}")

    console.print("\n[bold green]✅ Pipeline complete![/bold green]")
    console.print(f"[dim]Outputs: {cfg['paths']['processed']} | {cfg['paths']['reports']}[/dim]")


if __name__ == "__main__":
    run_pipeline()