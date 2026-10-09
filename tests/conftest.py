"""Ortak test yardımcıları. Fixture'lar yoksa otomatik üretir."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def ensure_fixtures() -> None:
    """Test korpusu yoksa üreteci çalıştır."""
    if not (FIXTURES / "benign.pkl").exists():
        tool = Path(__file__).parents[1] / "tools" / "make_fixtures.py"
        subprocess.run([sys.executable, str(tool), str(FIXTURES)], check=True)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES
