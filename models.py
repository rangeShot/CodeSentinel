"""
CodeSentinel – Pydantic models aligned with the OpenEnv base-class contract.

OpenEnv base classes (from openenv.core.env_server.types):
  Action      → BaseModel, extra="forbid", has metadata: Dict[str, Any]
  Observation → BaseModel, has done: bool, reward: float|None, metadata: Dict
  State       → BaseModel, extra="allow", has episode_id: str|None, step_count: int
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ActionType(str, Enum):
    inspect_file = "inspect_file"
    trace_route = "trace_route"
    flag_vulnerability = "flag_vulnerability"


class VulnType(str, Enum):
    sqli = "sqli"
    missing_auth = "missing_auth"
    ssrf = "ssrf"
    rce = "rce"
    unknown = "unknown"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


# ---------------------------------------------------------------------------
# Action  (extends OpenEnv Action contract)
# ---------------------------------------------------------------------------

class CodeSentinelAction(BaseModel):
    """Agent action submitted via POST /step."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    action_type: ActionType = Field(
        description="What the agent wants to do"
    )
    target: str = Field(
        description="File name (inspect_file), route path (trace_route), "
                    "or file:line_range (flag_vulnerability)"
    )
    details: Optional[str] = Field(
        default=None,
        description="Free-form detail: vuln type for flag_vulnerability, "
                    "entry-point route for trace_route"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Pass-through metadata (OpenEnv contract)"
    )


# ---------------------------------------------------------------------------
# Observation  (extends OpenEnv Observation contract)
# ---------------------------------------------------------------------------

class APIEndpoint(BaseModel):
    """A discovered Flask route."""
    route: str
    methods: List[str] = Field(default_factory=lambda: ["GET"])
    file: str
    line: int
    handler: str


class CallEdge(BaseModel):
    """Directed edge in the call graph."""
    caller: str      # "file.py::function_name"
    callee: str      # "file.py::function_name"
    call_site_line: int


class VulnFlag(BaseModel):
    """A vulnerability flagged by the agent."""
    vuln_type: VulnType
    file: str
    line: Optional[int] = None
    description: str
    severity: Severity = Severity.high


class CodeSentinelObservation(BaseModel):
    """
    Returned by reset() and step().
    'done' and 'reward' satisfy the OpenEnv Observation contract.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    # OpenEnv required fields
    done: bool = False
    reward: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # CodeSentinel-specific
    current_file: Optional[str] = None
    file_content: Optional[str] = None
    apis_found: List[APIEndpoint] = Field(default_factory=list)
    call_graph: List[CallEdge] = Field(default_factory=list)
    step_count: int = 0
    available_files: List[str] = Field(default_factory=list)
    message: str = ""


# ---------------------------------------------------------------------------
# State  (extends OpenEnv State contract)
# ---------------------------------------------------------------------------

class CodeSentinelState(BaseModel):
    """
    Returned by GET /state.
    episode_id and step_count satisfy the OpenEnv State contract.
    """

    model_config = ConfigDict(extra="allow", validate_assignment=True)

    # OpenEnv required fields
    episode_id: Optional[str] = None
    step_count: int = 0

    # CodeSentinel-specific
    task_name: str = ""
    files_inspected: List[str] = Field(default_factory=list)
    apis_found: List[APIEndpoint] = Field(default_factory=list)
    call_graph: List[CallEdge] = Field(default_factory=list)
    vulns_flagged: List[VulnFlag] = Field(default_factory=list)
    max_steps: int = 20
    done: bool = False
    final_score: Optional[float] = None


# ---------------------------------------------------------------------------
# HTTP request/response wrappers (FastAPI)
# ---------------------------------------------------------------------------

class ResetRequest(BaseModel):
    task: str = Field(default="easy", description="easy | medium | hard")
    seed: int = Field(default=42)
    episode_id: Optional[str] = None


class StepRequest(BaseModel):
    action: CodeSentinelAction


class ResetResponse(BaseModel):
    observation: CodeSentinelObservation
    reward: float = 0.0
    done: bool = False


class StepResponse(BaseModel):
    observation: CodeSentinelObservation
    reward: float
    done: bool
