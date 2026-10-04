from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import traceback
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from dependency_analyzer import DependencyAnalyzer
from vulnerability_scanner import VulnerabilityScanner
from supply_chain_analyzer import SupplyChainAnalyzer
from risk_scoring_engine import RiskScoringEngine


@dataclass
class ApplicationContext:
    root: Path
    config: dict[str, Any]
    policies: dict[str, Any]
    rules: dict[str, Any]
    started_at: datetime


@dataclass
class ExecutionResult:
    run_id: str
    started_at: str
    completed_at: str
    status: str
    input_count: int
    finding_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    report_path: str | None
    findings: list[dict[str, Any]]
    errors: list[str]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp() -> str:
    return utc_now().isoformat()


def make_run_id() -> str:
    return utc_now().strftime("sca-%Y%m%dT%H%M%S-%fZ")


def read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Configuration path is not a file: {path}")
    with path.open("r", encoding="utf-8") as stream:
        value = yaml.safe_load(stream)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"Expected a YAML mapping in {path}")
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, default=str)
        stream.write("\n")
    temporary.replace(path)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def configure_logging(level: str, log_file: str | None = None) -> None:
    numeric_level = getattr(logging,