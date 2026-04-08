"""
CodeSentinel – baseline inference script.

Uses an OpenAI-compatible LLM (via API_BASE_URL / MODEL_NAME / HF_TOKEN)
to drive the agent through all three tasks.

Output format (stdout):
  [START] {"task": "...", "model": "...", "timestamp": "..."}
  [STEP]  {"step": N, "action": "...", "observation": "...", "reward": 0.0}
  [END]   {"task": "...", "total_reward": 0.0, "steps": N, "status": "done"}

Environment variables:
  API_BASE_URL  – OpenAI-compatible base URL (default: https://api.openai.com/v1)
  MODEL_NAME    – model to use           (default: gpt-4o-mini)
  HF_TOKEN      – bearer token (used as API key)
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

import requests
from openai import OpenAI

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

API_BASE_URL = os.environ.get("API_BASE_URL", "https://api.openai.com/v1")
MODEL_NAME   = os.environ.get("MODEL_NAME",   "gpt-4o-mini")
HF_TOKEN     = os.environ.get("HF_TOKEN",     "")
ENV_BASE_URL = os.environ.get("ENV_BASE_URL", "http://localhost:8000")

MAX_HISTORY  = 20   # prune conversation history beyond this

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def log(tag: str, payload: dict) -> None:
    print(f"[{tag}] {json.dumps(payload)}", flush=True)


# ---------------------------------------------------------------------------
# Environment client (HTTP)
# ---------------------------------------------------------------------------

class EnvClient:
    def __init__(self, base_url: str = ENV_BASE_URL) -> None:
        self.base_url = base_url.rstrip("/")
        self._session = requests.Session()

    def reset(self, task: str, seed: int = 42) -> dict:
        r = self._session.post(
            f"{self.base_url}/reset",
            json={"task": task, "seed": seed},
            timeout=30,
        )
        r.raise_for_status()
        return r.json()

    def step(self, action: dict) -> dict:
        r = self._session.post(
            f"{self.base_url}/step",
            json={"action": action},
            timeout=30,
        )
        r.raise_for_status()
        return r.json()

    def state(self) -> dict:
        r = self._session.get(f"{self.base_url}/state", timeout=10)
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# LLM client
# ---------------------------------------------------------------------------

def make_llm_client() -> OpenAI:
    api_key = HF_TOKEN or "sk-placeholder"
    return OpenAI(api_key=api_key, base_url=API_BASE_URL)


# ---------------------------------------------------------------------------
# Action schema (passed as JSON schema to the model)
# ---------------------------------------------------------------------------

ACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "action_type": {
            "type": "string",
            "enum": ["inspect_file", "trace_route", "flag_vulnerability"],
            "description": (
                "inspect_file: read a file's contents. "
                "trace_route: trace the call chain for a route path. "
                "flag_vulnerability: report a discovered vulnerability."
            ),
        },
        "target": {
            "type": "string",
            "description": (
                "For inspect_file: the filename (e.g. 'app.py'). "
                "For trace_route: the route path (e.g. '/users'). "
                "For flag_vulnerability: the file where the vuln lives."
            ),
        },
        "details": {
            "type": "string",
            "description": (
                "For flag_vulnerability: include vuln_type (sqli/ssrf/rce/missing_auth), "
                "severity (critical/high/medium/low), and a brief description. "
                "For trace_route: the entry-point route if different from target."
            ),
        },
    },
    "required": ["action_type", "target"],
}

SYSTEM_PROMPT = """You are a security analyst AI. You will be given observations from a Python codebase environment.
Your job is to:
1. Inspect files to understand the code
2. Trace API routes to understand call flows
3. Flag security vulnerabilities (SQL injection, missing auth, SSRF, RCE)

Always respond with a single JSON object matching the action schema. No prose, no markdown — pure JSON only.
Prioritise: inspect all files first, then trace suspicious routes, then flag vulnerabilities."""


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------

def run_task(task_name: str, llm: OpenAI, env: EnvClient) -> dict[str, Any]:
    """Run the agent on one task. Returns summary dict."""

    # Reset environment
    reset_resp = env.reset(task=task_name)
    obs = reset_resp["observation"]

    log("START", {
        "task": task_name,
        "model": MODEL_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Task: {task_name}\n"
                f"Available files: {obs.get('available_files', [])}\n"
                f"Begin your analysis."
            ),
        },
    ]

    total_reward = 0.0
    step_num = 0
    done = reset_resp.get("done", False)

    while not done:
        step_num += 1

        # Prune history
        if len(messages) > MAX_HISTORY:
            messages = [messages[0]] + messages[-(MAX_HISTORY - 1):]

        # --- Ask LLM for next action ---
        try:
            completion = llm.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                response_format={"type": "json_object"},
                temperature=0.0,
            )
            raw_action_str = completion.choices[0].message.content or "{}"
            action_dict = json.loads(raw_action_str)
        except Exception as e:
            # Fallback: inspect the first uninspected file
            state_resp = env.state()
            inspected = set(state_resp.get("files_inspected", []))
            available = obs.get("available_files", [])
            remaining = [f for f in available if f not in inspected]
            if remaining:
                action_dict = {"action_type": "inspect_file", "target": remaining[0]}
            else:
                break

        # Validate action has required fields
        if "action_type" not in action_dict or "target" not in action_dict:
            action_dict = {"action_type": "inspect_file", "target": obs.get("available_files", ["app.py"])[0]}

        # --- Execute action ---
        try:
            step_resp = env.step(action_dict)
        except Exception as e:
            log("STEP", {"step": step_num, "action": action_dict, "observation": f"error: {e}", "reward": 0.0})
            break

        reward = step_resp.get("reward", 0.0)
        total_reward += reward
        done = step_resp.get("done", False)
        new_obs = step_resp.get("observation", {})

        obs_summary = {
            "message": new_obs.get("message", ""),
            "apis_found": len(new_obs.get("apis_found", [])),
            "call_graph_edges": len(new_obs.get("call_graph", [])),
            "step_count": new_obs.get("step_count", step_num),
        }

        log("STEP", {
            "step": step_num,
            "action": action_dict,
            "observation": obs_summary,
            "reward": round(reward, 4),
        })

        # Feed observation back into conversation
        obs_text = (
            f"Step {step_num} result:\n"
            f"  Message: {new_obs.get('message', '')}\n"
            f"  APIs found so far: {len(new_obs.get('apis_found', []))}\n"
            f"  Call graph edges: {len(new_obs.get('call_graph', []))}\n"
            f"  Current file content (first 800 chars):\n"
            f"  {str(new_obs.get('file_content', ''))[:800]}\n"
            f"  Available files: {new_obs.get('available_files', [])}\n"
            f"  Step reward: {round(reward, 4)}\n"
        )
        messages.append({"role": "assistant", "content": raw_action_str if 'raw_action_str' in dir() else json.dumps(action_dict)})
        messages.append({"role": "user", "content": obs_text})

        obs = new_obs

    # Final state
    try:
        final_state = env.state()
        final_score = final_state.get("final_score") or total_reward
    except Exception:
        final_score = total_reward

    status = "done" if done else "budget_exhausted"
    log("END", {
        "task": task_name,
        "total_reward": round(float(final_score), 4),
        "steps": step_num,
        "status": status,
    })

    return {
        "task": task_name,
        "total_reward": float(final_score),
        "steps": step_num,
        "status": status,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    llm = make_llm_client()
    env = EnvClient()

    # Verify environment is reachable
    try:
        health = requests.get(f"{ENV_BASE_URL}/health", timeout=10)
        health.raise_for_status()
    except Exception as e:
        print(f"[ERROR] Cannot reach environment at {ENV_BASE_URL}: {e}", file=sys.stderr)
        sys.exit(1)

    results = []
    for task in ("easy", "medium", "hard"):
        result = run_task(task, llm, env)
        results.append(result)

    # Summary
    print("\n[SUMMARY]", json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
