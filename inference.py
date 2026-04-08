"""
CodeSentinel – Inference Script
================================
Runs the LLM agent against all three tasks and emits structured stdout logs.

STDOUT FORMAT (mandatory):
    [START] task=<task_name> env=codesentinel model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>

Environment variables:
    API_BASE_URL     LLM endpoint  (default: https://router.huggingface.co/v1)
    MODEL_NAME       Model ID      (default: Qwen/Qwen2.5-72B-Instruct)
    HF_TOKEN         API key       (no default – must be set)
    ENV_BASE_URL     CodeSentinel server URL (default: http://localhost:7860)
"""

from __future__ import annotations

import os
import sys
import textwrap
from typing import List, Optional

import requests
from openai import OpenAI

# ---------------------------------------------------------------------------
# Config  – defaults only for API_BASE_URL and MODEL_NAME, NOT HF_TOKEN
# ---------------------------------------------------------------------------

API_BASE_URL  = os.getenv("API_BASE_URL") or "https://router.huggingface.co/v1"
MODEL_NAME    = os.getenv("MODEL_NAME")   or "Qwen/Qwen2.5-72B-Instruct"
HF_TOKEN      = os.getenv("HF_TOKEN")                      # no default
ENV_BASE_URL  = os.getenv("ENV_BASE_URL", "http://localhost:7860")

BENCHMARK     = "codesentinel"
MAX_STEPS     = 20
TEMPERATURE   = 0.0
SUCCESS_SCORE_THRESHOLD = 0.3   # score >= 0.3 counts as success

TASKS = ["easy", "medium", "hard"]

# ---------------------------------------------------------------------------
# Structured log helpers  (exact format required by the hackathon)
# ---------------------------------------------------------------------------

def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val  = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}",
        flush=True,
    )


# ---------------------------------------------------------------------------
# Environment HTTP client
# ---------------------------------------------------------------------------

class EnvClient:
    def __init__(self, base_url: str = ENV_BASE_URL) -> None:
        self._base    = base_url.rstrip("/")
        self._session = requests.Session()

    def reset(self, task: str, seed: int = 42) -> dict:
        r = self._session.post(f"{self._base}/reset", json={"task": task, "seed": seed}, timeout=30)
        r.raise_for_status()
        return r.json()

    def step(self, action: dict) -> dict:
        r = self._session.post(f"{self._base}/step", json={"action": action}, timeout=30)
        r.raise_for_status()
        return r.json()

    def state(self) -> dict:
        r = self._session.get(f"{self._base}/state", timeout=10)
        r.raise_for_status()
        return r.json()

    def close(self) -> None:
        self._session.close()


# ---------------------------------------------------------------------------
# LLM prompting
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = textwrap.dedent("""
    You are a security analyst AI operating inside a code analysis environment.

    At each step you must choose exactly ONE action from:
      inspect_file       – read a file's source code
      trace_route        – trace the call chain for a given route path
      flag_vulnerability – report a security vulnerability

    Respond with ONLY a JSON object. No prose, no markdown fences. Example:
      {"action_type": "inspect_file", "target": "app.py"}
      {"action_type": "trace_route", "target": "/users"}
      {"action_type": "flag_vulnerability", "target": "app.py", "details": "sqli critical: user input injected into SQL query"}

    Strategy:
    1. Inspect every file first to understand the code.
    2. Trace suspicious routes to map call flows.
    3. Flag each vulnerability with its type (sqli/ssrf/rce/missing_auth) and severity (critical/high/medium/low).
""").strip()


def choose_action(
    client: OpenAI,
    messages: list,
    available_files: list,
    inspected_files: list,
) -> dict:
    """Ask the LLM to choose the next action. Falls back to inspect if model fails."""
    import json

    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=messages,
            response_format={"type": "json_object"},
            temperature=TEMPERATURE,
        )
        raw = completion.choices[0].message.content or "{}"
        action = json.loads(raw)
        if "action_type" in action and "target" in action:
            return action
    except Exception as e:
        print(f"[DEBUG] LLM error: {e}", flush=True)

    # Fallback: inspect the next un-inspected file
    remaining = [f for f in available_files if f not in inspected_files and f.endswith(".py")]
    target = remaining[0] if remaining else (available_files[0] if available_files else "app.py")
    return {"action_type": "inspect_file", "target": target}


def build_obs_message(step_resp: dict, step_num: int) -> str:
    """Summarise the step result for the conversation history."""
    obs = step_resp.get("observation", {})
    content = obs.get("file_content") or ""
    return textwrap.dedent(f"""
        Step {step_num} result:
        Message : {obs.get('message', '')}
        APIs found : {len(obs.get('apis_found', []))} routes
        Call edges : {len(obs.get('call_graph', []))} edges
        Reward     : {step_resp.get('reward', 0):.2f}
        File preview (first 600 chars):
        {content[:600]}
        Available files: {obs.get('available_files', [])}
    """).strip()


# ---------------------------------------------------------------------------
# Single-task agent loop
# ---------------------------------------------------------------------------

def run_task(task_name: str, llm: OpenAI, env: EnvClient) -> None:
    import json

    rewards:  List[float] = []
    steps_taken = 0
    score       = 0.0
    success     = False
    error_msg: Optional[str] = None

    log_start(task=task_name, env=BENCHMARK, model=MODEL_NAME)

    try:
        reset_resp = env.reset(task=task_name)
        obs        = reset_resp["observation"]
        done       = reset_resp.get("done", False)

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Task: {task_name}\n"
                    f"Available files: {obs.get('available_files', [])}\n"
                    f"Start your analysis. Inspect files, trace routes, then flag vulnerabilities."
                ),
            },
        ]

        available_files = obs.get("available_files", [])
        inspected_files: list = []

        for step in range(1, MAX_STEPS + 1):
            if done:
                break

            steps_taken = step

            # Get action from LLM
            action = choose_action(llm, messages, available_files, inspected_files)

            # Track inspected files
            if action.get("action_type") == "inspect_file":
                inspected_files.append(action.get("target", ""))

            # Build readable action string for log
            details    = action.get("details", "")
            action_str = f"{action.get('action_type')}({action.get('target')}{(', ' + details) if details else ''})"

            # Execute step
            try:
                step_resp = env.step(action)
                reward    = float(step_resp.get("reward", 0.0))
                done      = step_resp.get("done", False)
                error_msg = None

                # Update available files from latest observation
                new_obs = step_resp.get("observation", {})
                if new_obs.get("available_files"):
                    available_files = new_obs["available_files"]

            except Exception as e:
                reward    = 0.0
                error_msg = str(e)
                done      = False

            rewards.append(reward)
            log_step(step=step, action=action_str, reward=reward, done=done, error=error_msg)

            if error_msg:
                break

            # Feed result back into conversation
            obs_text = build_obs_message(step_resp, step)
            messages.append({"role": "assistant", "content": json.dumps(action)})
            messages.append({"role": "user",      "content": obs_text})

            # Keep history from growing too large
            if len(messages) > 24:
                messages = [messages[0]] + messages[-22:]

        # Get final score from environment state
        try:
            state     = env.state()
            score     = float(state.get("final_score") or 0.0)
            if score == 0.0 and rewards:
                score = sum(rewards) / len(rewards)
        except Exception:
            score = sum(rewards) / len(rewards) if rewards else 0.0

        score   = min(max(score, 0.0), 1.0)
        success = score >= SUCCESS_SCORE_THRESHOLD

    except Exception as exc:
        error_msg = str(exc)
        print(f"[DEBUG] Task {task_name} failed: {exc}", flush=True)
    finally:
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    # Verify environment server is reachable
    try:
        r = requests.get(f"{ENV_BASE_URL}/health", timeout=10)
        r.raise_for_status()
    except Exception as e:
        print(f"[ERROR] Cannot reach environment at {ENV_BASE_URL}: {e}", file=sys.stderr)
        sys.exit(1)

    llm = OpenAI(api_key=HF_TOKEN or "sk-placeholder", base_url=API_BASE_URL)
    env = EnvClient(base_url=ENV_BASE_URL)

    try:
        for task in TASKS:
            run_task(task, llm, env)
    finally:
        env.close()


if __name__ == "__main__":
    main()
