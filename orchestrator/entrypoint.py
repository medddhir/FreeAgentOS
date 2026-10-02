"""Installed CLI bridge for the existing controller's module layout."""
from pathlib import Path
import sys


def main():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from cli import main as run
    return run()


def doctor_main():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from doctor import main as diagnose
    return diagnose()
