"""
utils/helpers.py
----------------
Shared utility functions used across the entire pipeline.
"""

import os
import re
import yaml
import json
import logging
from datetime import datetime
from pathlib import Path


def load_config(config_path: str = "configs/config.yaml") -> dict:
    """Load the central YAML config file."""
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def setup_logger(name: str, log_file: str = None, level=logging.INFO) -> logging.Logger:
    """Create a consistent logger for any module."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(level)
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger


EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

def is_valid_email(email: str) -> bool:
    if not email or not isinstance(email, str):
        return False
    return bool(EMAIL_REGEX.match(email.strip()))


def extract_domain(email: str) -> str:
    if is_valid_email(email):
        return email.strip().lower().split("@")[1]
    return ""


def normalize_email(email: str) -> str:
    return email.strip().lower() if email else ""


def normalize_username(username: str) -> str:
    if not username:
        return ""
    return re.sub(r"[^a-z0-9]", "", username.strip().lower())


def save_json(data, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def load_json(path: str):
    with open(path, "r") as f:
        return json.load(f)


def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def days_since(date_str: str) -> int:
    """Days elapsed since a given date string. Returns 9999 if unparseable."""
    if not date_str:
        return 9999
    formats = ["%Y-%m-%d", "%m/%d/%Y", "%Y/%m/%d", "%Y"]
    for fmt in formats:
        try:
            breach_date = datetime.strptime(str(date_str).strip(), fmt)
            return (datetime.now() - breach_date).days
        except ValueError:
            continue
    return 9999


def current_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")
