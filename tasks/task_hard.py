"""
Hard task specification.

Goal: discover the chained SSRF → RCE vulnerability across 15 files.

Attack chain:
  POST /api/gateway/proxy  (SSRF – no URL validation)
    → ProxyService.fetch(url)        (fetches internal URL)
    → internal http://localhost/api/exec/run
        → ExecService.run(script)    (RCE via shell=True)

Step budget: 20
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class HardTask:
    name: str = "hard"
    description: str = (
        "Analyse a 15-file Flask microservice. "
        "Discover the chained SSRF→RCE vulnerability and rank all findings by severity."
    )
    seed: int = 42
    max_steps: int = 20

    # Ground truth
    expected_routes: List[str] = field(default_factory=lambda: [
        "/proxy", "/status",            # gateway
        "/resource", "/batch",          # fetch
        "/run", "/eval",                # exec_api
        "/", "/deep",                   # health
        "/", "/<int:uid>",              # users
    ])

    # The chained vuln requires flagging both links
    expected_chain: List[dict] = field(default_factory=lambda: [
        {
            "vuln_type": "ssrf",
            "file": "api/gateway.py",
            "description_keywords": ["proxy", "url", "internal"],
        },
        {
            "vuln_type": "rce",
            "file": "services/exec_service.py",
            "description_keywords": ["shell", "subprocess", "eval"],
        },
    ])

    expected_severity_order: List[str] = field(default_factory=lambda: [
        "critical",   # rce / sqli
        "high",       # ssrf / missing_auth
        "medium",
    ])

    def instructions(self) -> str:
        return (
            "You are a senior security engineer auditing a 15-file Flask microservice.\n"
            "Your tasks:\n"
            "1. Map all 10 API endpoints.\n"
            "2. Identify ALL vulnerabilities in the codebase.\n"
            "3. Discover the chained attack: find how an SSRF vulnerability can be "
            "leveraged to trigger remote code execution in another service.\n"
            "4. Flag each vulnerability with its type (ssrf/rce/sqli/missing_auth) "
            "and severity (critical/high/medium/low).\n"
            "5. Rank your findings from most critical to least critical.\n\n"
            "Available actions:\n"
            "  inspect_file       – read a file\n"
            "  trace_route        – trace a route's call chain\n"
            "  flag_vulnerability – report a vuln (include vuln_type, severity, description)\n\n"
            f"Files: {{available_files}}\n\n"
            "Hint: look at how the gateway proxy endpoint handles the URL parameter "
            "and where that URL might ultimately be forwarded."
        )
