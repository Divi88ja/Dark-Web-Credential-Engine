"""
run.py
------
Root-level entry point for the Dark Web Credential Exposure Intelligence Platform.

Usage:
    python run.py
    python run.py --real-data
    python run.py --dashboard
    python run.py --real-data --dashboard
"""

import sys
import os
import argparse
import subprocess
import traceback


# ─────────────────────────────────────────────
# Ensure project root is on PYTHONPATH
# ─────────────────────────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))

if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


# ─────────────────────────────────────────────
# Import pipeline safely
# ─────────────────────────────────────────────
try:
    from src.pipeline import run_pipeline
except ImportError as e:
    print("❌ Failed to import pipeline module.")
    print("Make sure you're running this from the project root.")
    print(f"Error: {e}")
    sys.exit(1)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Dark Web Credential Exposure Intelligence Platform"
    )

    parser.add_argument(
        "--real-data",
        action="store_true",
        help="Use real breach data from data/raw/ instead of simulated data"
    )

    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch Streamlit dashboard after pipeline execution"
    )

    parser.add_argument(
        "--no-train",
        action="store_true",
        help="Skip model training (use existing model if available)"
    )

    args = parser.parse_args()

    use_simulated = not args.real_data

    print("\n🚀 Starting Pipeline...\n")
    print(f"Data Source     : {'REAL DATA' if args.real_data else 'SIMULATED DATA'}")
    print(f"Train Model     : {'NO' if args.no_train else 'YES'}")
    print(f"Launch Dashboard: {'YES' if args.dashboard else 'NO'}\n")

    # ─────────────────────────────────────────
    # Run pipeline safely
    # ─────────────────────────────────────────
    try:
        run_pipeline(use_simulated_data=use_simulated)
        print("\n✅ Pipeline completed successfully.\n")

    except Exception as e:
        print("\n❌ Pipeline failed.\n")
        traceback.print_exc()
        sys.exit(1)

    # ─────────────────────────────────────────
    # Launch dashboard (optional)
    # ─────────────────────────────────────────
    if args.dashboard:
        dashboard_path = os.path.join(ROOT, "dashboard", "app.py")

        if not os.path.exists(dashboard_path):
            print("❌ Dashboard file not found.")
            return

        print(f"\n🌐 Launching dashboard...\n")

        try:
            subprocess.run(
                [sys.executable, "-m", "streamlit", "run", dashboard_path],
                check=True
            )
        except subprocess.CalledProcessError:
            print("❌ Failed to launch Streamlit. Make sure it's installed:")
            print("   pip install streamlit")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    main()