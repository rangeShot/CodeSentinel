"""
server/app.py – OpenEnv-standard server entry point.

The openenv validate command checks for this file.
We re-export the FastAPI app from environment.py so the server
can be started either way:

    uvicorn server.app:app ...        (openenv standard)
    uvicorn environment:app ...       (direct / Dockerfile)

The [project.scripts] 'server' entry point calls main() below,
which is what `uv run server` and `openenv build` invoke.
"""

import os
import uvicorn

# Re-export the app so `uvicorn server.app:app` works
from environment import app  # noqa: F401


def main() -> None:
    """Entry point for `uv run server` and the openenv CLI."""
    uvicorn.run(
        "server.app:app",
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "7860")),
        workers=int(os.environ.get("WORKERS", "1")),
    )


if __name__ == "__main__":
    main()
