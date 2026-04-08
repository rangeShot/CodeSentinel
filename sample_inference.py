"""
Sample Inference Script — CodeSentinel
========================================
This is the reference implementation showing how the hackathon's sample
inference pattern maps to the CodeSentinel environment.

Compare with the official sample at:
  https://www.scaler.com/school-of-technology/meta-pytorch-hackathon/dashboard

Key differences from the echo-env sample:
  - Uses HTTP (no from_docker_image) since CodeSentinel is a REST server
  - action_type is one of: inspect_file / trace_route / flag_vulnerability
  - Score comes from the grader (API detection + vuln detection)

STDOUT FORMAT:
    [START] task=<task> env=codesentinel model=<model>
    [STEP]  step=<n> action=<str> reward=<0.00> done=<true|false> error=<null|msg>
    [END]   success=<true|false> steps=<n> score=<0.000> rewards=<r1,r2,...>
"""

import os
import textwrap
from typing import List, Optional

import requests
from openai import OpenAI

# ---------------------------------------------------------------------------
# Mandatory env vars  (defaults only for API_BASE_URL and MODEL_NAME)
# ---------------------------------------------------------------------------
API_BASE_URL = os.getenv("API_BASE_URL") or "https://router.huggingface.co/v1"
MODEL_NAME   = os.getenv("MODEL_NAME")   or "Qwen/Qwen2.5-72B-Instruct"
HF_TOKEN     = os.getenv("HF_TOKEN")                       # no default
ENV_BASE_URL = os.getenv("ENV_BASE_URL", "http://localhost:7860")

BENCHMARK    = "codesentinel"
TASK_NAME    = os.getenv("CODESENTINEL_TASK", "easy")
MAX_STEPS    = 20
SUCCESS_SCORE_THRESHOLD = 0.3

# ---------------------------------------------------------------------------
# Structured log helpers
# ---------------------------------------------------------------------------

def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} "
        f"done={str(done).lower()} error={error or 'null'}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} "
        f"score={score:.3f} rewards={rewards_str}",
        flush=True,
    )


# ---------------------------------------------------------------------------
# Environment client  (HTTP — no Docker needed, server runs separately)
# ---------------------------------------------------------------------------

class CodeSentinelClient:
    def __init__(self, base_url: str) -> None:
        self._base = base_url.rstrip("/")
        self._s    = requests.Session()

    def reset(self, task: str = "easy", seed: int = 42) -> dict:
        return self._s.post(f"{self._base}/reset", json={"task": task, "seed": seed}, timeout=30).json()

    def step(self, action: dict) -> dict:
        return self._s.post(f"{self._base}/step", json={"action": action}, timeout=30).json()

    def state(self) -> dict:
        return self._s.get(f"{self._base}/state", timeout=10).json()

    def close(self) -> None:
        self._s.close()


# ---------------------------------------------------------------------------
# LLM helper
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = textwrap.dedent("""
    You are a security analyst. Analyse the Python codebase step by step.
    Respond ONLY with a JSON object — no prose, no code fences.

    Actions available:
      {"action_type": "inspect_file",       "target": "<filename>"}
      {"action_type": "trace_route",        "target": "<route_path>"}
      {"action_type": "flag_vulnerability", "target": "<filename>", "details": "<vuln_type> <severity>: <description>"}

    Strategy: inspect every file → trace suspicious routes → flag all vulnerabilities.
""").strip()


def get_action(client: OpenAI, messages: list, available: list, inspected: list) -> dict:
    import json
    try:
        resp = client.chat.completions.create(
            model=MODEL_NAME,
            messages=messages,
            response_format={"type": "json_object"},
            temperature=0.0,
        )
        action = json.loads(resp.choices[0].message.content or "{}")
        if "action_type" in action and "target" in action:
            return action
    except Exception:
        pass
    # Fallback: inspect next un-inspected .py file
    remaining = [f for f in available if f not in inspected and f.endswith(".py")]
    return {"action_type": "inspect_file", "target": remaining[0] if remaining else available[0]}


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------

def run(task: str) -> None:
    import json

    rewards: List[float] = []
    steps_taken = 0
    score       = 0.0
    success     = False

    llm = OpenAI(api_key=HF_TOKEN or "sk-placeholder", base_url=API_BASE_URL)
    env = CodeSentinelClient(ENV_BASE_URL)

    log_start(task=task, env=BENCHMARK, model=MODEL_NAME)

    try:
        reset_resp      = env.reset(task=task)
        obs             = reset_resp["observation"]
        done            = reset_resp.get("done", False)
        available_files = obs.get("available_files", [])
        inspected: list = []

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": f"Task: {task}\nFiles: {available_files}\nBegin."},
        ]

        for step in range(1, MAX_STEPS + 1):
            if done:
                break
            steps_taken = step

            action    = get_action(llm, messages, available_files, inspected)
            if action.get("action_type") == "inspect_file":
                inspected.append(action["target"])

            details    = action.get("details", "")
            action_str = f"{action['action_type']}({action['target']}{(', ' + details) if details else ''})"

            error_msg: Optional[str] = None
            try:
                step_resp = env.step(action)
                reward    = float(step_resp.get("reward", 0.0))
                done      = step_resp.get("done", False)
                new_obs   = step_resp.get("observation", {})
                if new_obs.get("available_files"):
                    available_files = new_obs["available_files"]
            except Exception as e:
                reward    = 0.0
                error_msg = str(e)

            rewards.append(reward)
            log_step(step=step, action=action_str, reward=reward, done=done, error=error_msg)

            if error_msg:
                break

            obs_summary = (
                f"Step {step}: {new_obs.get('message','')} | "
                f"APIs: {len(new_obs.get('apis_found',[]))} | "
                f"File preview: {str(new_obs.get('file_content',''))[:400]}"
            )
            messages.append({"role": "assistant", "content": json.dumps(action)})
            messages.append({"role": "user",      "content": obs_summary})
            if len(messages) > 20:
                messages = [messages[0]] + messages[-18:]

        try:
            state = env.state()
            score = float(state.get("final_score") or 0.0)
        except Exception:
            pass
        if score == 0.0 and rewards:
            score = sum(rewards) / len(rewards)
        score   = min(max(score, 0.0), 1.0)
        success = score >= SUCCESS_SCORE_THRESHOLD

    finally:
        env.close()
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)


if __name__ == "__main__":
    run(TASK_NAME)
