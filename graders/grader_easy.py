"""
Easy task grader.

Score = 0.5 * api_f1  +  0.5 * vuln_detection

api_f1        : F1 of predicted routes vs ground-truth routes
vuln_detection: 1.0 if agent flagged ≥1 SQLi in app.py, else 0.0

All inputs are deterministic → score is fully deterministic.
"""

from __future__ import annotations

from typing import List

from models import APIEndpoint, VulnFlag
from tasks.task_easy import EasyTask


class GraderEasy:

    def __init__(self) -> None:
        self._task = EasyTask()

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def grade(
        self,
        apis_found: List[APIEndpoint],
        vulns_flagged: List[VulnFlag],
    ) -> float:
        api_score = self._api_f1(apis_found)
        vuln_score = self._vuln_detection(vulns_flagged)
        return round(0.5 * api_score + 0.5 * vuln_score, 4)

    def breakdown(
        self,
        apis_found: List[APIEndpoint],
        vulns_flagged: List[VulnFlag],
    ) -> dict:
        api_score = self._api_f1(apis_found)
        vuln_score = self._vuln_detection(vulns_flagged)
        return {
            "api_f1": round(api_score, 4),
            "vuln_detection": round(vuln_score, 4),
            "total": round(0.5 * api_score + 0.5 * vuln_score, 4),
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _api_f1(self, apis_found: List[APIEndpoint]) -> float:
        found_routes = {ep.route for ep in apis_found}
        expected = set(self._task.expected_routes)
        if not expected:
            return 1.0
        tp = len(found_routes & expected)
        precision = tp / len(found_routes) if found_routes else 0.0
        recall = tp / len(expected)
        if precision + recall == 0:
            return 0.0
        return (2 * precision * recall) / (precision + recall)

    def _vuln_detection(self, vulns_flagged: List[VulnFlag]) -> float:
        for ev in self._task.expected_vulns:
            matched = [
                v for v in vulns_flagged
                if v.vuln_type.value == ev["vuln_type"]
                and v.file == ev["file"]
            ]
            if not matched:
                return 0.0
            # Partial credit: description must contain at least one keyword
            kws = ev.get("description_keywords", [])
            if kws:
                desc_lower = matched[0].description.lower()
                keyword_hits = sum(1 for k in kws if k in desc_lower)
                if keyword_hits == 0:
                    return 0.5  # found the right file/type but vague description
        return 1.0
