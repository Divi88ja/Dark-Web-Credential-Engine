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


# ═══════════════════════════════════════════════════════════════
# NEW: Core pipeline function with dynamic input support
# ═══════════════════════════════════════════════════════════════
def run_pipeline_core(
    config_path: str = "config/settings.yaml",
    input_emails: list = None,
    use_simulated: bool = True,
    train_model: bool = False,
    verbose: bool = True,
):
    """
    ENHANCED PIPELINE CORE - Now returns DataFrame
    
    Parameters:
    -----------
    config_path : str
        Path to YAML configuration file
    input_emails : list or None
        List of email addresses to scan. If None, loads from employee file.
        Format: ['user1@example.com', 'user2@company.org', ...]
    use_simulated : bool
        If True, simulates breach data. If False, uses real breach files.
    train_model : bool
        If True, trains a new model. If False, loads pre-trained model (FAST MODE).
    verbose : bool
        If True, prints rich console output. If False, silent mode.
    
    Returns:
    --------
    pd.DataFrame
        Scored results with columns: email, breach_count, risk_score, risk_label, 
        sources, department, full_name, match_type, etc.
    """
    
    if verbose:
        print_pipeline_banner()
    
    # ──────────────────────────────────────────
    # STAGE 0: Config
    # ──────────────────────────────────────────
    if verbose:
        print_stage(0, "Loading Configuration")
    
    cfg = load_config(config_path)
    
    if not verbose:
        # Suppress logger in silent mode
        setup_logger("ERROR")
    else:
        setup_logger(cfg["project"]["log_level"])

    for path_key in ["raw_breaches", "processed", "internal", "models", "reports"]:
        ensure_dir(cfg["paths"][path_key])

    # ──────────────────────────────────────────
    # STAGE 1: Ingestion (with dynamic input support)
    # ──────────────────────────────────────────
    if verbose:
        print_stage(1, "Data Ingestion")

    # Handle dynamic email input
    if input_emails is not None and len(input_emails) > 0:
        # Clean and deduplicate emails
        cleaned_emails = list(set([e.strip().lower() for e in input_emails if e and "@" in e]))
        
        if verbose:
            console.print(f"[yellow]Using {len(cleaned_emails)} provided emails (external scan mode)[/yellow]")
        
        # Create employee dataframe from input emails
        employee_raw = pd.DataFrame({
            'email': cleaned_emails,
            'full_name': ['External User'] * len(cleaned_emails),
            'department': ['Unknown'] * len(cleaned_emails),
            'role': ['External'] * len(cleaned_emails),
            'role_sensitivity': [3] * len(cleaned_emails),  # Medium sensitivity default
        })
        
        # Extract domains
        employee_raw['domain'] = employee_raw['email'].str.split('@').str[1]
        
    else:
        # Load from employee file (standard mode)
        employee_raw = load_employee_file(cfg)
        if verbose:
            console.print(f"[green]✓[/green] Employees: {len(employee_raw):,}")
    
    # Load or simulate breach data
    if use_simulated or input_emails is not None:
        if verbose:
            console.print("[yellow]Generating simulated breach data...[/yellow]")
        run_simulation(cfg)
    
    breach_raw = ingest_all_breach_files(cfg)
    
    if len(breach_raw) == 0:
        if verbose:
            console.print("[red]ERROR: No breach data loaded[/red]")
        # Return empty dataframe with expected structure
        return pd.DataFrame(columns=[
            'email', 'full_name', 'department', 'breach_count', 
            'risk_score', 'risk_label', 'sources'
        ])

    if verbose:
        console.print(f"[green]✓[/green] Breach records: {len(breach_raw):,}")

    # ──────────────────────────────────────────
    # STAGE 2: Cleaning
    # ──────────────────────────────────────────
    if verbose:
        print_stage(2, "Data Cleaning")

    breach_clean, breach_rejected = clean_breach_data(breach_raw, cfg)
    employee_clean = clean_employee_data(employee_raw)
    breach_freq = compute_breach_frequency(breach_clean)

    # Save only in verbose mode
    if verbose:
        save_processed(breach_clean, "breach_clean.csv", cfg)
        save_processed(employee_clean, "employees_clean.csv", cfg)

    # ──────────────────────────────────────────
    # STAGE 3: NLP
    # ──────────────────────────────────────────
    if verbose:
        print_stage(3, "NLP Extraction")

    known_domains = set(employee_clean["domain"].unique())
    breach_enriched = enrich_breach_dataframe(breach_clean, known_domains)

    if verbose:
        save_processed(breach_enriched, "breach_enriched.csv", cfg)

    # ──────────────────────────────────────────
    # STAGE 4: Correlation
    # ──────────────────────────────────────────
    if verbose:
        print_stage(4, "Correlation")

    correlated = run_correlation_engine(breach_enriched, employee_clean, cfg)

    if len(correlated) == 0:
        if verbose:
            console.print("[yellow]No exposures found[/yellow]")
        # Return clean dataframe with zero risk
        result_df = employee_clean.copy()
        result_df['breach_count'] = 0
        result_df['risk_score'] = 0.0
        result_df['risk_label'] = 'LOW'
        result_df['sources'] = 'None'
        result_df['match_type'] = 'No Match'
        return result_df[['email', 'full_name', 'department', 'breach_count', 
                          'risk_score', 'risk_label', 'sources', 'match_type']]

    if verbose:
        save_processed(correlated, "correlated_hits.csv", cfg)

    # ──────────────────────────────────────────
    # STAGE 5: ML Scoring (with model caching)
    # ──────────────────────────────────────────
    if verbose:
        print_stage(5, "Risk Scoring")

    featured_df = engineer_features(correlated, breach_freq)

    # ✅ FAST MODE: Load pre-trained model OR train new one
    if train_model:
        if verbose:
            console.print("[yellow]Training new model...[/yellow]")
        model, scaler, _, _, feature_names = train_risk_model(featured_df, cfg)
        save_model(model, feature_names, cfg["paths"]["models"])
    else:
        # Load cached model (FAST!)
        try:
            if verbose:
                console.print("[cyan]Loading pre-trained model (fast mode)...[/cyan]")
            model, scaler, feature_names = load_model(cfg["paths"]["models"])
        except (FileNotFoundError, Exception) as e:
            if verbose:
                console.print(f"[yellow]Model not found. Training new model...[/yellow]")
            model, scaler, _, _, feature_names = train_risk_model(featured_df, cfg)
            save_model(model, feature_names, cfg["paths"]["models"])

    scored_df = compute_risk_scores(featured_df, model, scaler, feature_names, cfg)
    scored_df = generate_shap_explanations(scored_df, model, feature_names)

    if verbose:
        save_processed(scored_df, "scored_employees.csv", cfg)
        print_results_table(scored_df)

    # ──────────────────────────────────────────
    # STAGE 6: Alerts (optional in fast mode)
    # ──────────────────────────────────────────
    if verbose:
        print_stage(6, "Alert Generation")
        alerts_df = generate_alerts(scored_df, cfg)

        if len(alerts_df) > 0:
            generate_html_report(alerts_df, cfg["paths"]["reports"] + "alert_report.html")
            save_alerts_csv(alerts_df, cfg["paths"]["reports"] + "alerts.csv")

        console.print(
            "\n[bold yellow]Insight:[/bold yellow] "
            "High-risk exposure is concentrated in privileged roles and recent breaches."
        )

    # ──────────────────────────────────────────
    # FINAL SUMMARY
    # ──────────────────────────────────────────
    if verbose:
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

    from pathlib import Path

    # FORCE correct filename for Streamlit app
    BASE_DIR = Path(__file__).resolve().parent

    output_path = BASE_DIR / "data" / "processed" / "risk_scored_employees.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    scored_df.to_csv(output_path, index=False)

    print(f"✅ FINAL FILE SAVED AT: {output_path}")

    # RETURN DATAFRAME (key change for UI integration)
    return scored_df


@click.command()
@click.option("--config", default="config/settings.yaml", help="Path to config YAML")
@click.option("--skip-simulate", is_flag=True, help="Skip data simulation")
@click.option("--train-model", is_flag=True, help="Train new model instead of loading cached")
@click.option("--no-dashboard", is_flag=True, help="Skip launching dashboard")
def run_pipeline(config: str, skip_simulate: bool, train_model: bool, no_dashboard: bool):
    """CLI entry point - now uses run_pipeline_core"""
    
    # Call the core pipeline function
    _ = run_pipeline_core(
        config_path=config,
        input_emails=None,  # Use employee file in CLI mode
        use_simulated=not skip_simulate,
        train_model=train_model,
        verbose=True  # Always verbose in CLI mode
    )


if __name__ == "__main__":
    run_pipeline()