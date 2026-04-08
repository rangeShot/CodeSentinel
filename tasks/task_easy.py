"""
Easy task specification.

Goal: agent must find all 2 API routes in the 3-file Flask app
      AND flag the 1 SQLi vulnerability.

Step budget: 20 (shared env default)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class EasyTask:
    name: str = "easy"
    description: str = (
        "Analyse a small 3-file Flask application. "
        "Identify all API endpoints and flag any SQL-injection vulnerabilities."
    )
    seed: int = 42
    max_steps: int = 20

    # Ground truth (must stay in sync with simulator/codebase.py)
    expected_routes: List[str] = field(default_factory=lambda: [
        "/users",
        "/users/<user_id>",
    ])

    expected_vulns: List[dict] = field(default_factory=lambda: [
        {
            "vuln_type": "sqli",
            "file": "app.py",
            "description_keywords": ["injection", "user_id", "query"],
        }
    ])

    def instructions(self) -> str:
        return (
            "You are a security analyst. The codebase is a small Flask web application.\n"
            "Your tasks:\n"
            "1. Inspect all files and identify every API endpoint (route path + HTTP methods).\n"
            "2. Trace how requests flow through the code.\n"
            "3. Flag any SQL-injection vulnerabilities with the exact file and line.\n\n"
            "Available actions:\n"
            "  inspect_file   – read the contents of a file\n"
            "  trace_route    – trace the call flow starting from a route\n"
            "  flag_vulnerability – report a vulnerability (vuln_type, file, description)\n\n"
            f"Files in this codebase: {{available_files}}\n"
            "Submit your findings by flagging vulnerabilities. "
            "The episode ends when you exhaust your step budget."
        )
