---
title: CodeSentinel
emoji: 🛡️
colorFrom: red
colorTo: indigo
sdk: docker
app_port: 7860
---

# CodeSentinel

An OpenEnv-compliant reinforcement learning environment where an AI agent analyses synthetic Python codebases to identify API endpoints, trace call flows, and detect security vulnerabilities.

Built for the [Meta × PyTorch × Hugging Face OpenEnv AI Hackathon](https://www.scaler.com/school-of-technology/meta-pytorch-hackathon).

---

## Overview

The agent operates on a deterministic synthetic Flask codebase and can take three types of actions:

| Action | Description |
|--------|-------------|
| `inspect_file` | Read the contents of a file |
| `trace_route` | Trace the call chain starting from an API route |
| `flag_vulnerability` | Report a security vulnerability with type and severity |

### Tasks

| Task | Files | Routes | Vulnerabilities |
|------|-------|--------|----------------|
| Easy | 3 | 2 | 1 × SQL injection |
| Medium | 8 | 5 | Missing auth on 3 routes |
| Hard | 15 | 10 | Chained SSRF → RCE |

---

## Quick Start

### Run locally

```bash
pip install -r requirements.txt
uvicorn environment:app --host 0.0.0.0 --port 8000
```

### Run with Docker

```bash
docker build -t codesentinel .
docker run -p 8000:8000 codesentinel
```

### Run inference

```bash
export API_BASE_URL="https://api-inference.huggingface.co/v1"
export MODEL_NAME="meta-llama/Llama-3.1-8B-Instruct"
export HF_TOKEN="hf_..."
export ENV_BASE_URL="http://localhost:8000"

python inference.py
```

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/reset` | POST | Start a new episode (`{"task": "easy", "seed": 42}`) |
| `/step` | POST | Execute an action |
| `/state` | GET | Current episode state |
| `/health` | GET | Health check |
| `/metadata` | GET | Environment description |
| `/schema` | GET | JSON schemas for Action / Observation / State |

### Reset

```bash
curl -X POST http://localhost:8000/reset \
  -H "Content-Type: application/json" \
  -d '{"task": "easy", "seed": 42}'
```

### Step

```bash
curl -X POST http://localhost:8000/step \
  -H "Content-Type: application/json" \
  -d '{
    "action": {
      "action_type": "inspect_file",
      "target": "app.py"
    }
  }'
```

### Flag a vulnerability

```bash
curl -X POST http://localhost:8000/step \
  -H "Content-Type: application/json" \
  -d '{
    "action": {
      "action_type": "flag_vulnerability",
      "target": "app.py",
      "details": "sqli critical: user_id injected directly into SQL query without parameterisation"
    }
  }'
```

---

## Reward Structure

### Easy
```
score = 0.5 × api_F1  +  0.5 × vuln_detection
```

### Medium
```
score = 0.4 × call_flow_accuracy  +  0.3 × api_F1  +  0.3 × vuln_score
```

### Hard
```
score = 0.35 × chain_discovery  +  0.35 × severity_ranking  +  0.30 × efficiency
```

All scores are deterministic floats in [0.0, 1.0].

---

## Project Structure

```
CodeSentinel/
├── environment.py          # Core env + FastAPI HTTP server
├── models.py               # Pydantic: Action, Observation, State
├── simulator/
│   ├── codebase.py         # Deterministic synthetic codebase generator
│   ├── api_extractor.py    # AST-based Flask route extractor
│   └── vuln_patterns.py    # Regex + AST vulnerability scanner
├── tasks/
│   ├── task_easy.py        # 3-file app, 2 routes, 1 SQLi
│   ├── task_medium.py      # 8-file app, 5 routes, missing auth
│   └── task_hard.py        # 15-file app, 10 routes, SSRF→RCE chain
├── graders/
│   ├── grader_easy.py
│   ├── grader_medium.py
│   └── grader_hard.py
├── inference.py            # LLM baseline agent (OpenAI-compatible)
├── openenv.yaml            # OpenEnv manifest
├── Dockerfile
└── requirements.txt
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `API_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible API base URL |
| `MODEL_NAME` | `gpt-4o-mini` | Model to use for inference |
| `HF_TOKEN` | — | Bearer token (used as API key) |
| `ENV_BASE_URL` | `http://localhost:8000` | Base URL of the running environment |
