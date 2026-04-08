"""
CodeSentinel – typed HTTP/WebSocket client.

Follows the OpenEnv client pattern so this Space can be installed
and used as a typed package:

    pip install git+https://huggingface.co/spaces/<username>/codesentinel

Usage (sync):
    from client import CodeSentinelClient, CodeSentinelAction, ActionType

    with CodeSentinelClient(base_url="https://<space>.hf.space").sync() as env:
        result = env.reset(task="easy")
        result = env.step(CodeSentinelAction(action_type=ActionType.inspect_file, target="app.py"))
        print(result.observation.message)

Usage (async):
    import asyncio
    from client import CodeSentinelClient, CodeSentinelAction, ActionType

    async def main():
        async with CodeSentinelClient(base_url="http://localhost:7860") as env:
            result = await env.reset(task="easy")
            result = await env.step(CodeSentinelAction(action_type=ActionType.inspect_file, target="app.py"))

    asyncio.run(main())
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from typing import Optional

import requests

from models import (
    ActionType,
    CodeSentinelAction,
    CodeSentinelObservation,
    CodeSentinelState,
    ResetResponse,
    StepResponse,
)

# Re-export for convenience
__all__ = [
    "CodeSentinelClient",
    "CodeSentinelAction",
    "CodeSentinelObservation",
    "CodeSentinelState",
    "ActionType",
]


class StepResult:
    """Thin wrapper matching OpenEnv StepResult contract."""

    def __init__(self, observation: CodeSentinelObservation, reward: float, done: bool) -> None:
        self.observation = observation
        self.reward = reward
        self.done = done

    def __repr__(self) -> str:
        return f"StepResult(reward={self.reward}, done={self.done}, msg={self.observation.message!r})"


class _SyncClient:
    """Synchronous wrapper around the HTTP API."""

    def __init__(self, base_url: str) -> None:
        self._base = base_url.rstrip("/")
        self._session = requests.Session()

    def reset(self, task: str = "easy", seed: int = 42) -> StepResult:
        r = self._session.post(
            f"{self._base}/reset",
            json={"task": task, "seed": seed},
            timeout=30,
        )
        r.raise_for_status()
        data = r.json()
        return StepResult(
            observation=CodeSentinelObservation(**data["observation"]),
            reward=data["reward"],
            done=data["done"],
        )

    def step(self, action: CodeSentinelAction) -> StepResult:
        r = self._session.post(
            f"{self._base}/step",
            json={"action": action.model_dump()},
            timeout=30,
        )
        r.raise_for_status()
        data = r.json()
        return StepResult(
            observation=CodeSentinelObservation(**data["observation"]),
            reward=data["reward"],
            done=data["done"],
        )

    def state(self) -> CodeSentinelState:
        r = self._session.get(f"{self._base}/state", timeout=10)
        r.raise_for_status()
        return CodeSentinelState(**r.json())

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "_SyncClient":
        return self

    def __exit__(self, *_) -> None:
        self.close()


class CodeSentinelClient:
    """
    Async-first client for the CodeSentinel environment.

    Async usage:
        async with CodeSentinelClient(base_url="...") as client:
            result = await client.reset(task="easy")
            result = await client.step(action)

    Sync usage (via .sync()):
        with CodeSentinelClient(base_url="...").sync() as client:
            result = client.reset(task="easy")
            result = client.step(action)
    """

    def __init__(self, base_url: str = "http://localhost:7860") -> None:
        self._base = base_url.rstrip("/")
        self._sync_client: Optional[_SyncClient] = None

    # ------------------------------------------------------------------
    # Async API
    # ------------------------------------------------------------------

    async def reset(self, task: str = "easy", seed: int = 42) -> StepResult:
        return await asyncio.get_event_loop().run_in_executor(
            None, lambda: self._get_sync().reset(task=task, seed=seed)
        )

    async def step(self, action: CodeSentinelAction) -> StepResult:
        return await asyncio.get_event_loop().run_in_executor(
            None, lambda: self._get_sync().step(action)
        )

    async def state(self) -> CodeSentinelState:
        return await asyncio.get_event_loop().run_in_executor(
            None, self._get_sync().state
        )

    async def close(self) -> None:
        if self._sync_client:
            self._sync_client.close()
            self._sync_client = None

    async def __aenter__(self) -> "CodeSentinelClient":
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Sync wrapper
    # ------------------------------------------------------------------

    def sync(self) -> _SyncClient:
        """Return a synchronous context-manager client."""
        return _SyncClient(self._base)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_sync(self) -> _SyncClient:
        if self._sync_client is None:
            self._sync_client = _SyncClient(self._base)
        return self._sync_client
