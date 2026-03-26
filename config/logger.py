"""
config/logger.py
----------------
Centralized colored logging for the entire project.
Import this everywhere instead of using print() statements.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime

# Try colorlog for prettier output; fall back to stdlib if not installed
try:
    import colorlog
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

LOGS_DIR = Path(__file__).resolve().parent.parent / "logs"
LOGS_DIR.mkdir(exist_ok=True)


def get_logger(name: str) -> logging.Logger:
    """
    Returns a logger with both console (colored) and file handlers.

    Usage:
        from config.logger import get_logger
        logger = get_logger(__name__)
        logger.info("Pipeline started")
        logger.warning("Missing field in record")
        logger.error("File not found")
    """
    logger = logging.getLogger(name)

    # Prevent duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # ── Console handler (colored if colorlog is available) ──────────────────
    if HAS_COLOR:
        fmt = "%(log_color)s%(asctime)s [%(levelname)-8s]%(reset)s %(name)s → %(message)s"
        console_fmt = colorlog.ColoredFormatter(
            fmt,
            datefmt="%H:%M:%S",
            log_colors={
                "DEBUG":    "cyan",
                "INFO":     "green",
                "WARNING":  "yellow",
                "ERROR":    "red",
                "CRITICAL": "red,bg_white",
            },
        )
    else:
        fmt = "%(asctime)s [%(levelname)-8s] %(name)s → %(message)s"
        console_fmt = logging.Formatter(fmt, datefmt="%H:%M:%S")

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_fmt)

    # ── File handler (plain text, full debug) ───────────────────────────────
    log_file = LOGS_DIR / f"pipeline_{datetime.now().strftime('%Y%m%d')}.log"
    file_fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s → %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_fmt)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger
