"""
Medium task specification.

Goal: trace the full call chain for the update_profile route
      AND identify all missing-auth vulnerabilities across 8 files.

Step budget: 20
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class MediumTask:
    name: str = "medium"
    description: str = (
        "Analyse an 8-file Flask application using blueprints. "
        "Trace call flows and find all endpoints missing authentication."
    )
    seed: int = 42
    max_steps: int = 20

    # Ground truth
    expected_routes: List[str] = field(default_factory=lambda: [
        "/",            # blueprints/users.py list_users
        "/<int:user_id>",
        "/<int:user_id>/profile",
        "/",            # blueprints/admin.py admin_list_users
        "/users/<int:uid>/delete",
        "/",            # blueprints/reports.py list_reports
    ])

    # Routes that should be flagged as missing auth
    expected_missing_auth_handlers: List[str] = field(default_factory=lambda: [
        "update_profile",
        "admin_list_users",
        "admin_delete_user",
    ])

    # Expected call chain for update_profile
    expected_call_chain: List[str] = field(default_factory=lambda: [
        "blueprints/users.py::update_profile",
        "services/user_service.py::UserService.update",
    ])

    def instructions(self) -> str:
        return (
            "You are a security analyst reviewing a medium-complexity Flask application.\n"
            "Your tasks:\n"
            "1. Map all API endpoints across all blueprints.\n"
            "2. For each route, check whether @require_auth is applied.\n"
            "3. Trace the call chain for the PUT /api/users/<id>/profile endpoint "
            "and document each function call.\n"
            "4. Flag every endpoint missing authentication.\n\n"
            "Available actions:\n"
            "  inspect_file      – read a file's contents\n"
            "  trace_route       – trace a route's execution path\n"
            "  flag_vulnerability – report a missing-auth or other vulnerability\n\n"
            f"Files: {{available_files}}"
        )
