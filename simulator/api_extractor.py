"""
AST-based Flask route extractor.

Parses Python source code to find @app.route / @<blueprint>.route decorators
and returns structured APIEndpoint records.
"""

from __future__ import annotations

import ast
from typing import List

from models import APIEndpoint


class APIExtractor:
    """Extract Flask API endpoints from Python source using the AST."""

    def extract(self, filename: str, source: str) -> List[APIEndpoint]:
        """Return all routes found in *source* (the content of *filename*)."""
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

        endpoints: List[APIEndpoint] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for decorator in node.decorator_list:
                ep = self._parse_decorator(decorator, node, filename)
                if ep is not None:
                    endpoints.append(ep)
        return endpoints

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_decorator(
        self,
        decorator: ast.expr,
        func_node: ast.FunctionDef,
        filename: str,
    ) -> APIEndpoint | None:
        """
        Match patterns:
          @app.route('/path', methods=['GET', 'POST'])
          @<bp_name>.route('/path')
        """
        if not isinstance(decorator, ast.Call):
            return None

        func = decorator.func
        if not isinstance(func, ast.Attribute) or func.attr != "route":
            return None

        # First positional arg is the path
        if not decorator.args:
            return None
        path_node = decorator.args[0]
        if not isinstance(path_node, ast.Constant) or not isinstance(path_node.value, str):
            return None
        route_path = path_node.value

        # Optional methods= keyword
        methods: List[str] = ["GET"]
        for kw in decorator.keywords:
            if kw.arg == "methods" and isinstance(kw.value, ast.List):
                methods = [
                    elt.value
                    for elt in kw.value.elts
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                ]

        return APIEndpoint(
            route=route_path,
            methods=methods,
            file=filename,
            line=func_node.lineno,
            handler=func_node.name,
        )

    def extract_from_codebase(
        self, files: dict[str, str]
    ) -> List[APIEndpoint]:
        """Run extraction across every file in the codebase dict."""
        found: List[APIEndpoint] = []
        for filename, source in files.items():
            if filename.endswith(".py") and source.strip():
                found.extend(self.extract(filename, source))
        return found
