"""
hibp_example.py
===============
Standalone usage examples for hibp_client.py.

Run:
    python hibp_example.py
"""

import logging
import json

# Configure logging so you can see what the client is doing
logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")

from src.ingestion.hibp_client import HIBPClient, build_client_from_config


# ─────────────────────────────────────────────────────────────────────────────
# Example 1 – Direct client usage
# ─────────────────────────────────────────────────────────────────────────────

def example_direct():
    print("\n" + "="*60)
    print("Example 1: Direct HIBPClient usage")
    print("="*60)

    client = HIBPClient(
        api_key="YOUR_API_KEY",          # replace with real key
        rate_limit_per_min=10,
        use_cache=True,
    )

    email = "test@example.com"
    breaches = client.get_breaches_for_email(email)

    if breaches:
        print(f"\nFound {len(breaches)} breach(es) for {email}:\n")
        for b in breaches:
            print(f"  Breach  : {b['breach_name']}")
            print(f"  Date    : {b['breach_date']}")
            print(f"  Severity: {b['severity']}")
            print(f"  Classes : {', '.join(b['data_classes'][:3])}")
            print(f"  Domain  : {b['raw_domain']}")
            print()
    else:
        print(f"\nNo breaches found for {email} (or API call failed – check logs)")


# ─────────────────────────────────────────────────────────────────────────────
# Example 2 – Load from config (recommended for production)
# ─────────────────────────────────────────────────────────────────────────────

def example_from_config():
    print("\n" + "="*60)
    print("Example 2: Build client from settings.yaml")
    print("="*60)

    import yaml
    with open("config/settings.yaml") as f:
        config = yaml.safe_load(f)

    # build_client_from_config reads the `ingestion.hibp` block
    client = build_client_from_config(config.get("ingestion", config))

    if client is None:
        print("HIBP disabled or api_key not set – see config/settings.yaml")
        return

    email = "security@example.com"
    breaches = client.get_breaches_for_email(email)
    print(f"\nRaw output for {email}:")
    print(json.dumps(breaches, indent=2, default=str))


# ─────────────────────────────────────────────────────────────────────────────
# Example 3 – Run the full pipeline in hybrid mode
# ─────────────────────────────────────────────────────────────────────────────

def example_full_pipeline():
    print("\n" + "="*60)
    print("Example 3: Full pipeline with use_hibp=True")
    print("="*60)

    from pipeline import run_pipeline

    result = run_pipeline(
        use_hibp=True,
        config_path="config/settings.yaml",
        employee_emails=["alice@corp.com", "bob@corp.com"],   # small sample
    )

    print("\nPipeline result:")
    print(f"  Data sources : {result['data_sources']}")
    print(f"  Total records: {result['risk_summary'].get('total_records', 0)}")
    print(f"  HIBP records : {result['risk_summary'].get('hibp_records', 0)}")
    print(f"  Alerts raised: {len(result['alerts'])}")


# ─────────────────────────────────────────────────────────────────────────────
# Example 4 – Inspect the cache
# ─────────────────────────────────────────────────────────────────────────────

def example_inspect_cache():
    print("\n" + "="*60)
    print("Example 4: Inspect local cache")
    print("="*60)

    from pathlib import Path
    cache_dir = Path("cache/hibp")
    files = list(cache_dir.glob("*.json"))

    if not files:
        print("Cache is empty – run example_direct() first.")
        return

    print(f"Found {len(files)} cached response(s):\n")
    for f in files:
        data = json.loads(f.read_text())
        print(f"  File        : {f.name}")
        print(f"  Masked email: {data.get('masked_email')}")
        print(f"  Cached at   : {data.get('cached_at')}")
        print(f"  Breaches    : {len(data.get('breaches', []))}")
        print()


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    example_direct()
    example_from_config()
    # example_full_pipeline()   # uncomment once your pipeline stubs are wired up
    example_inspect_cache()
