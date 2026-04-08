"""
Hard task grader.

Score = 0.35 * chain_discovery
      + 0.35 * severity_ranking
      + 0.30 * efficiency

chain_discovery   : did agent flag BOTH the SSRF and RCE links of the chain?
severity_ranking  : are critical findings ranked before high/medium ones?
efficiency        : 1 - (steps_used / max_steps), rewarding fewer steps
"""

from __future__ import annotations

from typing import List

from models import VulnFlag
from tasks.task_hard import HardTask


class GraderHard:

    def __init__(self) -> None:
        self._task = HardTask()

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def grade(
        self,
        vulns_flagged: List[VulnFlag],
        steps_used: int,
        max_steps: int = 20,
    ) -> float:
        chain = self._chain_discovery(vulns_flagged)
        ranking = self._severity_ranking(vulns_flagged)
        efficiency = self._efficiency(steps_used, max_steps)
        return round(0.35 * chain + 0.35 * ranking + 0.30 * efficiency, 4)

    def breakdown(
        self,
        vulns_flagged: List[VulnFlag],
        steps_used: int,
        max_steps: int = 20,
    ) -> dict:
        chain = self._chain_discovery(vulns_flagged)
        ranking = self._severity_ranking(vulns_flagged)
        efficiency = self._efficiency(steps_used, max_steps)
        return {
            "chain_discovery": round(chain, 4),
            "severity_ranking": round(ranking, 4),
            "efficiency": round(efficiency, 4),
            "total": round(0.35 * chain + 0.35 * ranking + 0.30 * efficiency, 4),
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _chain_discovery(self, vulns_flagged: List[VulnFlag]) -> float:
        """1.0 if both SSRF and RCE chain links are flagged, 0.5 if only one."""
        expected = self._task.expected_chain
        scores: List[float] = []
        for ev in expected:
            matched = [
                v for v in vulns_flagged
                if v.vuln_type.value == ev["vuln_type"]
                and ev["file"] in v.file
            ]
            if matched:
                kws = ev.get("description_keywords", [])
                if kws:
                    desc_lower = matched[0].description.lower()
                    kw_hits = sum(1 for k in kws if k in desc_lower)
                    scores.append(0.5 + 0.5 * (kw_hits / len(kws)))
                else:
                    scores.append(1.0)
            else:
                scores.append(0.0)
        return sum(scores) / len(scores) if scores else 0.0

    def _severity_ranking(self, vulns_flagged: List[VulnFlag]) -> float:
        """
        Check that critical findings appear before high, high before medium.
        Returns fraction of consecutive ordering constraints that are satisfied.
        """
        if not vulns_flagged:
            return 0.0
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        ranked = [severity_rank.get(v.severity.value, 3) for v in vulns_flagged]
        if len(ranked) < 2:
            # Can't verify ordering with fewer than 2 items
            return 1.0 if ranked and ranked[0] == 0 else 0.5
        violations = sum(
            1 for i in range(len(ranked) - 1) if ranked[i] > ranked[i + 1]
        )
        return 1.0 - violations / (len(ranked) - 1)

    def _efficiency(self, steps_used: int, max_steps: int) -> float:
        if max_steps <= 0:
            return 0.0
        steps_used = max(0, min(steps_used, max_steps))
        return 1.0 - steps_used / max_steps
