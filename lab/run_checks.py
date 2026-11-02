#!/usr/bin/env python3
"""Run actual checks and record source hashes, runtime and individual outcomes."""
import argparse
import hashlib
import json
import platform
import sqlite3
import sys
import unittest
from pathlib import Path


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.records.append({"check": test.id(), "status": "passed"})

    def addFailure(self, test, error):
        super().addFailure(test, error)
        self.records.append({"check": test.id(), "status": "failed"})

    def addError(self, test, error):
        super().addError(test, error)
        self.records.append({"check": test.id(), "status": "error"})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    suite = unittest.defaultTestLoader.discover(str(root), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(suite)
    report = {"version": "1.1.0-lab", "scope": "Author-defined synthetic local tests; not independent validation, production security, novelty, adoption or business impact.",
              "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
              "operating_system": platform.system(), "architecture": platform.machine(),
              "source_sha256": {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                                for name in ("authority_lab.py", "test_authority_lab.py", "run_checks.py")},
              "checks_run": result.testsRun, "passed": len([r for r in result.records if r["status"] == "passed"]),
              "successful": result.wasSuccessful(), "results": sorted(result.records, key=lambda r: r["check"])}
    encoded = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end="")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
