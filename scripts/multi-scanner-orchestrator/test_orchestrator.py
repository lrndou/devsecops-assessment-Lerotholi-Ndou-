"""Tests for the Multi-Scanner Orchestrator."""
import json
import subprocess
import sys
import os

SCRIPT = os.path.join(os.path.dirname(__file__), "orchestrator.py")


def test_invalid_target():
    """Test: invalid target directory exits with code 2."""
    result = subprocess.run(
        [sys.executable, SCRIPT, "--target", "/nonexistent/path"],
        capture_output=True, text=True
    )
    assert result.returncode == 2
    assert "not a valid directory" in result.stderr


def test_valid_target_json_output():
    """Test: valid target produces JSON output with expected fields."""

    target = os.path.dirname(__file__)
    result = subprocess.run(
        [sys.executable, SCRIPT, "--target", target, "--format", "json"],
        capture_output=True, text=True
    )

    assert result.returncode == 0
    report = json.loads(result.stdout)
    assert "risk_score" in report
    assert "findings" in report
    assert "scanners" in report
    assert report["risk_score"] >= 0


def test_table_format():
    """Test: table format produces readable output."""
    target = os.path.dirname(__file__)
    result = subprocess.run(
        [sys.executable, SCRIPT, "--target", target, "--format", "table"],
        capture_output=True, text=True
    )
    assert result.returncode == 0
    assert "SECURITY SCAN REPORT" in result.stdout


if __name__ == "__main__":
    test_invalid_target()
    print("PASS: test_invalid_target")
    test_valid_target_json_output()
    print("PASS: test_valid_target_json_output")
    test_table_format()
    print("PASS: test_table_format")
    print("\nAll tests passed!")
