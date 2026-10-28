"""
conftest.py - shared fixtures for extanalyze test suite.
"""
import sys
from pathlib import Path

# Ensure the package is importable from the repo root
sys.path.insert(0, str(Path(__file__).parent.parent))
