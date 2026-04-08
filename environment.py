"""
CodeSentinel – core RL environment + FastAPI HTTP server.

Exposes the OpenEnv-compatible REST API:
  POST /reset   → ResetResponse
  POST /step    → StepResponse
  GET  /state   → CodeSentinelState
  GET  /health  → {"status": "healthy"}
  GET  /metadata→ environment description
  GET  /schema  → JSON schemas for Action / Observation / State
"""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import FastAPI, HTTPException

from models import (
    ActionType,
    CallEdge,
    CodeSentinelAction,
    CodeSentinelObservation,
    CodeSentinelState,
    ResetRequest,
    ResetResponse,
    StepRequest,
    StepResponse,
    VulnFlag,
    VulnType,
    Severity,
)
from simulator.codebase import SyntheticCodebase
from simulator.api_extractor import APIExtractor
from simulator.vuln_patterns import VulnScanner
from tasks import TASK_REGISTRY
from graders import GRADER_REGISTRY


# ---------------------------------------------------------------------------
# Core environment
# ---------------------------------------------------------------------------

class CodeSentinelEnv:
    """
    Stateful RL environment for one episode.
    Thread-safety: each HTTP request creates/reads from the singleton below;
    for true concurrency use session IDs (out of scope for hackathon).
    """

    def __init__(self) -> None:
        self._state: Optional[CodeSentinelState] = None
        self._codebase: Optional[SyntheticCodebase] = None
        self._task_spec = None
        self._extractor = APIExtractor()
        self._scanner = VulnScanner()

    # ------------------------------------------------------------------
    # OpenEnv API
    # ------------------------------------------------------------------

    def reset(self, task: str = "easy", seed: int = 42, episode_id: Optional[str] = None) -> tuple[CodeSentinelObservation, float, bool]:
        """Initialise a new episode."""
        task_cls = TASK_REGISTRY.get(task)
        if task_cls is None:
            raise ValueError(f"Unknown task: {task!r}. Choose from: {list(TASK_REGISTRY)}")

        self._task_spec = task_cls(seed=seed)
        self._codebase = SyntheticCodebase(task=task, seed=seed)

        eid = episode_id or str(uuid.uuid4())
        self._state = CodeSentinelState(
            episode_id=eid,
            step_count=0,
            task_name=task,
            files_inspected=[],
            apis_found=[],
            call_graph=[],
            vulns_flagged=[],
            max_steps=self._task_spec.max_steps,
            done=False,
            final_score=None,
        )

        obs = CodeSentinelObservation(
            done=False,
            reward=None,
            current_file=None,
            file_content=None,
            apis_found=[],
            call_graph=[],
            step_count=0,
            available_files=self._codebase.file_list(),
            message=(
                f"Episode started. Task: {task}. "
                f"Files available: {self._codebase.file_list()}"
            ),
        )
        return obs, 0.0, False

    def step(self, action: CodeSentinelAction) -> tuple[CodeSentinelObservation, float, bool]:
        """Execute one agent action and return (observation, reward, done)."""
        if self._state is None or self._codebase is None:
            raise RuntimeError("Call reset() before step()")

        self._state.step_count += 1
        step_reward = 0.0

        # --- Dispatch action ---
        if action.action_type == ActionType.inspect_file:
            obs, step_reward = self._handle_inspect(action)

        elif action.action_type == ActionType.trace_route:
            obs, step_reward = self._handle_trace(action)

        elif action.action_type == ActionType.flag_vulnerability:
            obs, step_reward = self._handle_flag(action)

        else:
            obs = self._current_obs(f"Unknown action type: {action.action_type}")

        # --- Check done ---
        done = self._state.step_count >= self._state.max_steps or self._state.done
        if done and self._state.final_score is None:
            self._state.final_score = self._compute_final_score()
            self._state.done = True
            step_reward = self._state.final_score

        obs.done = done
        obs.reward = step_reward
        obs.step_count = self._state.step_count
        return obs, step_reward, done

    @property
    def state(self) -> CodeSentinelState:
        if self._state is None:
            raise RuntimeError("Call reset() first")
        return self._state

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------

    def _handle_inspect(self, action: CodeSentinelAction) -> tuple[CodeSentinelObservation, float]:
        filename = action.target
        content = self._codebase.get_file(filename)
        if not content:
            return self._current_obs(f"File not found: {filename}"), 0.0

        # Extract APIs from this file
        new_apis = self._extractor.extract(filename, content)
        existing_routes = {ep.route for ep in self._state.apis_found}
        for ep in new_apis:
            if ep.route not in existing_routes:
                self._state.apis_found.append(ep)
                existing_routes.add(ep.route)

        if filename not in self._state.files_inspected:
            self._state.files_inspected.append(filename)

        # Small reward for inspecting a new file
        reward = 0.05 if filename not in self._state.files_inspected else 0.01

        obs = CodeSentinelObservation(
            current_file=filename,
            file_content=content,
            apis_found=list(self._state.apis_found),
            call_graph=list(self._state.call_graph),
            available_files=self._codebase.file_list(),
            message=f"Inspected {filename}. Found {len(new_apis)} route(s).",
        )
        return obs, reward

    def _handle_trace(self, action: CodeSentinelAction) -> tuple[CodeSentinelObservation, float]:
        """
        Trace the call chain starting from a route.
        We do a simplified static trace: find the handler for the route,
        then resolve imports to build call edges.
        """
        route = action.target
        # Find the handler for this route
        handler_ep = next(
            (ep for ep in self._state.apis_found if ep.route == route), None
        )
        if handler_ep is None:
            return self._current_obs(
                f"Route {route!r} not found in discovered APIs. Inspect files first."
            ), 0.0

        new_edges = self._static_trace(handler_ep.file, handler_ep.handler)
        existing = {(e.caller, e.callee) for e in self._state.call_graph}
        added = 0
        for edge in new_edges:
            key = (edge.caller, edge.callee)
            if key not in existing:
                self._state.call_graph.append(edge)
                existing.add(key)
                added += 1

        reward = 0.1 * added
        obs = CodeSentinelObservation(
            current_file=handler_ep.file,
            file_content=self._codebase.get_file(handler_ep.file),
            apis_found=list(self._state.apis_found),
            call_graph=list(self._state.call_graph),
            available_files=self._codebase.file_list(),
            message=f"Traced route {route!r}. Added {added} call edge(s).",
        )
        return obs, reward

    def _handle_flag(self, action: CodeSentinelAction) -> tuple[CodeSentinelObservation, float]:
        """Record a vulnerability flag from the agent."""
        # Parse vuln_type from details or target
        raw_type = (action.details or action.target).lower()
        vuln_type = VulnType.unknown
        for vt in VulnType:
            if vt.value in raw_type:
                vuln_type = vt
                break

        # Parse severity
        severity = Severity.high
        if "critical" in raw_type:
            severity = Severity.critical
        elif "medium" in raw_type:
            severity = Severity.medium
        elif "low" in raw_type:
            severity = Severity.low

        flag = VulnFlag(
            vuln_type=vuln_type,
            file=action.target,
            description=action.details or "",
            severity=severity,
        )
        self._state.vulns_flagged.append(flag)

        # Small per-flag reward; final score settled at episode end
        reward = 0.05
        obs = CodeSentinelObservation(
            apis_found=list(self._state.apis_found),
            call_graph=list(self._state.call_graph),
            available_files=self._codebase.file_list(),
            message=f"Vulnerability flagged: {vuln_type.value} in {action.target}.",
        )
        return obs, reward

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _current_obs(self, message: str) -> CodeSentinelObservation:
        return CodeSentinelObservation(
            apis_found=list(self._state.apis_found) if self._state else [],
            call_graph=list(self._state.call_graph) if self._state else [],
            available_files=self._codebase.file_list() if self._codebase else [],
            message=message,
        )

    def _static_trace(self, filename: str, handler: str) -> list[CallEdge]:
        """
        Walk the AST of *filename* to find functions called by *handler*,
        then try to resolve them to other files in the codebase.
        Returns a list of CallEdge objects.
        """
        source = self._codebase.get_file(filename)
        if not source:
            return []
        try:
            import ast as _ast
            tree = _ast.parse(source)
        except SyntaxError:
            return []

        # Find the target function node
        target_fn = None
        for node in _ast.walk(tree):
            if isinstance(node, _ast.FunctionDef) and node.name == handler:
                target_fn = node
                break
        if target_fn is None:
            return []

        edges: list[CallEdge] = []
        caller_label = f"{filename}::{handler}"

        for node in _ast.walk(target_fn):
            if not isinstance(node, _ast.Call):
                continue
            callee_name = self._resolve_callee(node)
            if callee_name:
                # Try to find which file defines this name
                callee_file = self._find_definition(callee_name)
                callee_label = f"{callee_file}::{callee_name}" if callee_file else callee_name
                edges.append(CallEdge(
                    caller=caller_label,
                    callee=callee_label,
                    call_site_line=node.lineno,
                ))
        return edges

    def _resolve_callee(self, call_node) -> Optional[str]:
        import ast as _ast
        func = call_node.func
        if isinstance(func, _ast.Name):
            return func.id
        if isinstance(func, _ast.Attribute):
            if isinstance(func.value, _ast.Name):
                return f"{func.value.id}.{func.attr}"
        return None

    def _find_definition(self, name: str) -> Optional[str]:
        """Heuristic: return first file that defines the given name."""
        base = name.split(".")[0]
        import ast as _ast
        for fname, src in self._codebase.files.items():
            if not src.strip():
                continue
            try:
                tree = _ast.parse(src)
            except SyntaxError:
                continue
            for node in _ast.walk(tree):
                if isinstance(node, (_ast.FunctionDef, _ast.ClassDef)) and node.name == base:
                    return fname
        return None

    def _compute_final_score(self) -> float:
        """Run the appropriate grader and return 0.0–1.0."""
        task_name = self._state.task_name
        grader_cls = GRADER_REGISTRY.get(task_name)
        if grader_cls is None:
            return 0.0
        grader = grader_cls()

        if task_name == "easy":
            return grader.grade(
                apis_found=self._state.apis_found,
                vulns_flagged=self._state.vulns_flagged,
            )
        elif task_name == "medium":
            return grader.grade(
                apis_found=self._state.apis_found,
                call_graph=self._state.call_graph,
                vulns_flagged=self._state.vulns_flagged,
            )
        elif task_name == "hard":
            return grader.grade(
                vulns_flagged=self._state.vulns_flagged,
                steps_used=self._state.step_count,
                max_steps=self._state.max_steps,
            )
        return 0.0


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CodeSentinel",
    description="OpenEnv RL environment – AI agent analyses Python codebases for security vulnerabilities.",
    version="1.0.0",
)

# Single shared environment instance (stateful, single-session)
_env = CodeSentinelEnv()


@app.post("/reset", response_model=ResetResponse)
def reset(req: ResetRequest) -> ResetResponse:
    obs, reward, done = _env.reset(
        task=req.task,
        seed=req.seed,
        episode_id=req.episode_id,
    )
    return ResetResponse(observation=obs, reward=reward, done=done)


@app.post("/step", response_model=StepResponse)
def step(req: StepRequest) -> StepResponse:
    try:
        obs, reward, done = _env.step(req.action)
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return StepResponse(observation=obs, reward=reward, done=done)


@app.get("/state", response_model=CodeSentinelState)
def state() -> CodeSentinelState:
    try:
        return _env.state
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/health")
def health() -> dict:
    return {"status": "healthy"}


@app.get("/metadata")
def metadata() -> dict:
    return {
        "name": "CodeSentinel",
        "version": "1.0.0",
        "description": (
            "AI agent analyses synthetic Python codebases to identify API endpoints, "
            "trace call flows, and detect security vulnerabilities (SQLi, SSRF, RCE, missing auth)."
        ),
        "tasks": ["easy", "medium", "hard"],
        "action_space": ["inspect_file", "trace_route", "flag_vulnerability"],
        "observation_space": ["file_content", "apis_found", "call_graph", "step_count"],
        "reward_range": [0.0, 1.0],
    }


@app.get("/schema")
def schema() -> dict:
    return {
        "action": CodeSentinelAction.model_json_schema(),
        "observation": CodeSentinelObservation.model_json_schema(),
        "state": CodeSentinelState.model_json_schema(),
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("environment:app", host="0.0.0.0", port=8000, reload=False)
