"""
logger.py — Structured logging setup for PHP2Shell Scanner.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime


def setup_logger(
    debug: bool = False,
    verbose: bool = False,
    log_file: str = None
) -> logging.Logger:
    """
    Configure and return the root logger for the scanner.

    Args:
        debug:    Enable DEBUG level logging (most verbose).
        verbose:  Enable INFO level logging.
        log_file: Optional path to write log output to a file.

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger("php2shell")
    logger.handlers.clear()

    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    logger.setLevel(level)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler — only attach when debug/verbose is on
    if debug or verbose:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # File handler
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError as exc:
            logger.warning("Cannot open log file %s: %s", log_file, exc)

    # Suppress noisy third-party loggers
    for noisy in ("urllib3", "requests", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.ERROR)

    return logger
