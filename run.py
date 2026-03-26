"""
run.py
------
Root-level entry point. Run this instead of `python -m src.pipeline`.

Usage (from the project root folder):
    python run.py
    python run.py --real-data        # use files in data/raw/ instead of simulated
    python run.py --dashboard        # launch Streamlit after pipeline completes
"""

import sys
import os
import argparse

# ── Ensure the project root is always on the Python path ──────
# This is the fix for "No module named src.pipeline"
# When you double-click run.py or call it from any directory,
# this line makes sure Python can find the src/ package.
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.pipeline import run_pipeline


def main():
    parser = argparse.ArgumentParser(
        description="Dark Web Credential Exposure Correlation Engine"
    )
    parser.add_argument(
        "--real-data",
        action="store_true",
        help="Read breach files from data/raw/ instead of using simulated data"
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch the Streamlit dashboard after the pipeline completes"
    )
    args = parser.parse_args()

    use_simulated = not args.real_data
    run_pipeline(use_simulated_data=use_simulated)

    if args.dashboard:
        import subprocess
        dashboard_path = os.path.join(ROOT, "dashboard", "app.py")
        print(f"\nLaunching dashboard: streamlit run {dashboard_path}\n")
        subprocess.run([sys.executable, "-m", "streamlit", "run", dashboard_path])


if __name__ == "__main__":
    main()
