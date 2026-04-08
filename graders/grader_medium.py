"""
Medium task grader.

Score = 0.4 * call_flow_accuracy
      + 0.3 * api_score
      + 0.3 * vuln_score

call_flow_accuracy : fraction of expected call-chain edges the agent traced
api_score          : F1 of routes found vs ground truth
vuln_score         : fraction of missing-auth handlers the agent flagged
"""

from __future__ import annotations

from typing import List

from models import APIEndpoint, CallEdge, VulnFlag
from tasks.task_medium import MediumTask


class GraderMedium:

    def __init__(self) -> None:
        self._task = MediumTask()

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def grade(
        self,
        apis_found: List[APIEndpoint],
        call_graph: List[CallEdge],
        vulns_flagged: List[VulnFlag],
    ) -> float:
        cf = self._call_flow(call_graph)
        api = self._api_f1(apis_found)
        vuln = self._vuln_score(vulns_flagged)
        return round(0.4 * cf + 0.3 * api + 0.3 * vuln, 4)

    def breakdown(
        self,
        apis_found: List[APIEndpoint],
        call_graph: List[CallEdge],
        vulns_flagged: List[VulnFlag],
    ) -> dict:
        cf = self._call_flow(call_graph)
        api = self._api_f1(apis_found)
        vuln = self._vuln_score(vulns_flagged)
        return {
            "call_flow_accuracy": round(cf, 4),
            "api_f1": round(api, 4),
            "vuln_score": round(vuln, 4),
            "total": round(0.4 * cf + 0.3 * api + 0.3 * vuln, 4),
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _call_flow(self, call_graph: List[CallEdge]) -> float:
        """Fraction of expected chain nodes covered by traced edges."""
        chain = self._task.expected_call_chain
        if not chain:
            return 1.0
        # Represent chain as set of (caller, callee) string pairs
        expected_edges = {
            (chain[i], chain[i + 1]) for i in range(len(chain) - 1)
        }
        found_edges = {(e.caller, e.callee) for e in call_graph}
        if not expected_edges:
            return 1.0
        hits = len(found_edges & expected_edges)
        return hits / len(expected_edges)

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

    def _vuln_score(self, vulns_flagged: List[VulnFlag]) -> float:
        """Fraction of expected missing-auth handlers flagged."""
        expected = set(self._task.expected_missing_auth_handlers)
        if not expected:
            return 1.0
        # Match by handler name appearing in the description
        flagged_handlers = set()
        for v in vulns_flagged:
            if v.vuln_type.value == "missing_auth":
                for handler in expected:
                    if handler in v.description:
                        flagged_handlers.add(handler)
        return len(flagged_handlers) / len(expected)
