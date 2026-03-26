"""
ingestion/ingestor.py
---------------------
Automated ingestion pipeline. Handles CSV files, text dumps,
and the simulated generator. This is your pipeline entry point.

Design decision: We use a class so state (loaded files, errors)
is easy to track and test.
"""

import os
import pandas as pd
from pathlib import Path
from src.utils.helpers import setup_logger, load_config

logger = setup_logger(__name__)


class BreachDataIngestor:
    """
    Ingest breach data from multiple sources into a unified DataFrame.

    Supported sources:
      - CSV files (standard breach export format)
      - Text files (colon-separated: email:password or email:hash)
      - Simulated data (via data_generator.py)
    """

    # Column aliases: maps common column names in real breach datasets
    # to our internal standard names.
    COLUMN_ALIASES = {
        "e-mail":         "email",
        "mail":           "email",
        "user_email":     "email",
        "user":           "username",
        "user_name":      "username",
        "name":           "username",
        "pass":           "password_hash",
        "password":       "password_hash",
        "hashed_password":"password_hash",
        "source":         "breach_source",
        "date":           "breach_date",
        "leaked_date":    "breach_date",
    }

    def __init__(self, config_path: str = "configs/config.yaml"):
        self.config = load_config(config_path)
        self.raw_data_path = self.config["paths"]["raw_data"]
        self.loaded_files = []
        self.errors = []

    def ingest_csv(self, filepath: str) -> pd.DataFrame:
        """
        Load a CSV breach file. Handles different delimiters and encodings.
        """
        logger.info(f"Ingesting CSV: {filepath}")
        try:
            # Try common delimiters
            for sep in [",", ";", "\t", "|"]:
                try:
                    df = pd.read_csv(
                        filepath,
                        sep=sep,
                        encoding="utf-8",
                        on_bad_lines="skip",     # skip malformed rows
                        low_memory=False
                    )
                    if len(df.columns) > 1:
                        df = self._normalize_columns(df)
                        self.loaded_files.append(filepath)
                        logger.info(f"  Loaded {len(df)} rows from {filepath}")
                        return df
                except Exception:
                    continue
        except Exception as e:
            self.errors.append(f"CSV error {filepath}: {e}")
            logger.error(f"Failed to ingest CSV {filepath}: {e}")
        return pd.DataFrame()

    def ingest_text_dump(self, filepath: str) -> pd.DataFrame:
        """
        Parse raw text dumps in formats like:
          email:password
          email:hash:username
          username:email:hash

        This is the most common format for dark-web credential dumps.
        """
        logger.info(f"Ingesting text dump: {filepath}")
        records = []

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split(":")
                    record = {"raw_line": line, "breach_source": Path(filepath).stem}

                    if len(parts) >= 2:
                        # Heuristic: if part[0] looks like email, it is.
                        if "@" in parts[0]:
                            record["email"]         = parts[0]
                            record["password_hash"] = parts[1] if len(parts) > 1 else ""
                            record["username"]      = parts[2] if len(parts) > 2 else ""
                        else:
                            record["username"]      = parts[0]
                            record["email"]         = parts[1] if "@" in parts[1] else ""
                            record["password_hash"] = parts[2] if len(parts) > 2 else ""

                    records.append(record)

        except Exception as e:
            self.errors.append(f"Text dump error {filepath}: {e}")
            logger.error(f"Failed to ingest text dump: {e}")
            return pd.DataFrame()

        df = pd.DataFrame(records)
        self.loaded_files.append(filepath)
        logger.info(f"  Parsed {len(df)} records from text dump")
        return df

    def ingest_all_from_directory(self) -> pd.DataFrame:
        """
        Auto-discover and ingest all supported files from the raw data directory.
        This is your automated pipeline trigger.
        """
        raw_path = Path(self.raw_data_path)
        if not raw_path.exists():
            logger.warning(f"Raw data directory not found: {raw_path}")
            return pd.DataFrame()

        all_dfs = []

        for file in raw_path.iterdir():
            if file.suffix.lower() == ".csv":
                df = self.ingest_csv(str(file))
            elif file.suffix.lower() in [".txt", ".log"]:
                df = self.ingest_text_dump(str(file))
            else:
                continue

            if not df.empty:
                df["source_file"] = file.name
                all_dfs.append(df)

        if not all_dfs:
            logger.warning("No files ingested from directory")
            return pd.DataFrame()

        combined = pd.concat(all_dfs, ignore_index=True)
        logger.info(f"Total records ingested: {len(combined)}")
        return combined

    def _normalize_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Rename columns to match our internal standard."""
        rename_map = {}
        for col in df.columns:
            normalized = col.strip().lower().replace(" ", "_")
            if normalized in self.COLUMN_ALIASES:
                rename_map[col] = self.COLUMN_ALIASES[normalized]
            else:
                rename_map[col] = normalized
        return df.rename(columns=rename_map)

    def get_summary(self) -> dict:
        return {
            "files_loaded": len(self.loaded_files),
            "files":        self.loaded_files,
            "errors":       self.errors,
        }
