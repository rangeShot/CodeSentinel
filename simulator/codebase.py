"""
Deterministic synthetic Flask codebase generator.

All randomness is seeded so the same (task, seed) always produces
the exact same files.  No external APIs are called.

Difficulty levels
-----------------
easy   : 3 files, 2 routes, 1 SQLi
medium : 8 files, 5 routes, missing-auth + insecure-direct-object-ref
hard   : 15 files, 10 routes, chained SSRF → RCE pattern
"""

from __future__ import annotations

import random
import textwrap
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class SyntheticCodebase:
    task: str = "easy"
    seed: int = 42
    files: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        rng = random.Random(self.seed)
        if self.task == "easy":
            self.files = _generate_easy(rng)
        elif self.task == "medium":
            self.files = _generate_medium(rng)
        elif self.task == "hard":
            self.files = _generate_hard(rng)
        else:
            raise ValueError(f"Unknown task: {self.task!r}")

    def file_list(self) -> List[str]:
        return sorted(self.files.keys())

    def get_file(self, name: str) -> str:
        return self.files.get(name, "")


# ---------------------------------------------------------------------------
# Easy – 3 files, 2 routes, 1 SQLi
# ---------------------------------------------------------------------------

def _generate_easy(rng: random.Random) -> Dict[str, str]:
    _ = rng  # seed consumed deterministically; unused here but kept for API
    return {
        "app.py": textwrap.dedent("""\
            from flask import Flask, request, g
            from db import get_connection
            from utils import format_response

            app = Flask(__name__)

            @app.route('/users', methods=['GET'])
            def list_users():
                conn = get_connection()
                rows = conn.execute('SELECT id, name FROM users').fetchall()
                return format_response(rows)

            @app.route('/users/<user_id>', methods=['GET'])
            def get_user(user_id):
                conn = get_connection()
                # VULN: SQLi – user_id injected directly into query
                query = f"SELECT * FROM users WHERE id = {user_id}"
                row = conn.execute(query).fetchone()
                return format_response(row)

            if __name__ == '__main__':
                app.run(debug=True)
        """),

        "db.py": textwrap.dedent("""\
            import sqlite3

            _DB_PATH = 'users.db'

            def get_connection():
                conn = sqlite3.connect(_DB_PATH)
                conn.row_factory = sqlite3.Row
                return conn
        """),

        "utils.py": textwrap.dedent("""\
            import json
            from flask import jsonify

            def format_response(data):
                if data is None:
                    return jsonify({'error': 'not found'}), 404
                if hasattr(data, 'keys'):
                    return jsonify(dict(data))
                return jsonify([dict(r) for r in data])
        """),
    }


# ---------------------------------------------------------------------------
# Medium – 8 files, 5 routes, missing-auth + insecure direct object ref
# ---------------------------------------------------------------------------

def _generate_medium(rng: random.Random) -> Dict[str, str]:
    _ = rng
    return {
        "app.py": textwrap.dedent("""\
            from flask import Flask
            from blueprints.users import users_bp
            from blueprints.admin import admin_bp
            from blueprints.reports import reports_bp

            app = Flask(__name__)
            app.register_blueprint(users_bp, url_prefix='/api/users')
            app.register_blueprint(admin_bp, url_prefix='/api/admin')
            app.register_blueprint(reports_bp, url_prefix='/api/reports')

            if __name__ == '__main__':
                app.run()
        """),

        "blueprints/__init__.py": "",

        "blueprints/users.py": textwrap.dedent("""\
            from flask import Blueprint, request, jsonify
            from services.user_service import UserService
            from middleware.auth import require_auth

            users_bp = Blueprint('users', __name__)

            @users_bp.route('/', methods=['GET'])
            @require_auth
            def list_users():
                return jsonify(UserService.get_all())

            @users_bp.route('/<int:user_id>', methods=['GET'])
            @require_auth
            def get_user(user_id):
                return jsonify(UserService.get_by_id(user_id))

            @users_bp.route('/<int:user_id>/profile', methods=['PUT'])
            def update_profile(user_id):
                # VULN: missing @require_auth – any caller can update any user
                data = request.json
                return jsonify(UserService.update(user_id, data))
        """),

        "blueprints/admin.py": textwrap.dedent("""\
            from flask import Blueprint, request, jsonify
            from services.admin_service import AdminService

            admin_bp = Blueprint('admin', __name__)

            @admin_bp.route('/users', methods=['GET'])
            def admin_list_users():
                # VULN: no auth check on admin endpoint
                return jsonify(AdminService.get_all_users())

            @admin_bp.route('/users/<int:uid>/delete', methods=['DELETE'])
            def admin_delete_user(uid):
                # VULN: no auth check
                AdminService.delete_user(uid)
                return jsonify({'status': 'deleted'})
        """),

        "blueprints/reports.py": textwrap.dedent("""\
            from flask import Blueprint, jsonify
            from middleware.auth import require_auth
            from services.report_service import ReportService

            reports_bp = Blueprint('reports', __name__)

            @reports_bp.route('/', methods=['GET'])
            @require_auth
            def list_reports():
                return jsonify(ReportService.get_all())
        """),

        "middleware/auth.py": textwrap.dedent("""\
            from functools import wraps
            from flask import request, jsonify

            def require_auth(f):
                @wraps(f)
                def decorated(*args, **kwargs):
                    token = request.headers.get('Authorization')
                    if not token or not token.startswith('Bearer '):
                        return jsonify({'error': 'unauthorized'}), 401
                    return f(*args, **kwargs)
                return decorated
        """),

        "services/user_service.py": textwrap.dedent("""\
            class UserService:
                _store = {1: {'id': 1, 'name': 'alice'}, 2: {'id': 2, 'name': 'bob'}}

                @classmethod
                def get_all(cls):
                    return list(cls._store.values())

                @classmethod
                def get_by_id(cls, uid):
                    return cls._store.get(uid)

                @classmethod
                def update(cls, uid, data):
                    if uid in cls._store:
                        cls._store[uid].update(data)
                    return cls._store.get(uid)
        """),

        "services/admin_service.py": textwrap.dedent("""\
            from services.user_service import UserService

            class AdminService:
                @classmethod
                def get_all_users(cls):
                    return UserService.get_all()

                @classmethod
                def delete_user(cls, uid):
                    UserService._store.pop(uid, None)
        """),

        "services/report_service.py": textwrap.dedent("""\
            class ReportService:
                @classmethod
                def get_all(cls):
                    return [{'id': 1, 'title': 'Q1 Report'}]
        """),
    }


# ---------------------------------------------------------------------------
# Hard – 15 files, 10 routes, chained SSRF → RCE
# ---------------------------------------------------------------------------

def _generate_hard(rng: random.Random) -> Dict[str, str]:
    _ = rng
    return {
        "app.py": textwrap.dedent("""\
            from flask import Flask
            from api.gateway import gateway_bp
            from api.fetch import fetch_bp
            from api.exec_api import exec_bp
            from api.health import health_bp
            from api.users import users_bp

            app = Flask(__name__)
            app.register_blueprint(gateway_bp, url_prefix='/api/gateway')
            app.register_blueprint(fetch_bp,   url_prefix='/api/fetch')
            app.register_blueprint(exec_bp,    url_prefix='/api/exec')
            app.register_blueprint(health_bp,  url_prefix='/api/health')
            app.register_blueprint(users_bp,   url_prefix='/api/users')

            if __name__ == '__main__':
                app.run()
        """),

        "api/__init__.py": "",

        "api/gateway.py": textwrap.dedent("""\
            from flask import Blueprint, request, jsonify
            from services.proxy_service import ProxyService
            from middleware.auth import require_auth

            gateway_bp = Blueprint('gateway', __name__)

            @gateway_bp.route('/proxy', methods=['POST'])
            @require_auth
            def proxy_request():
                url = request.json.get('url')
                # VULN: SSRF – url not validated, forwards to internal services
                result = ProxyService.fetch(url)
                return jsonify({'result': result})

            @gateway_bp.route('/status', methods=['GET'])
            def gateway_status():
                return jsonify({'status': 'ok'})
        """),

        "api/fetch.py": textwrap.dedent("""\
            from flask import Blueprint, request, jsonify
            from services.fetch_service import FetchService
            from middleware.auth import require_auth

            fetch_bp = Blueprint('fetch', __name__)

            @fetch_bp.route('/resource', methods=['GET'])
            @require_auth
            def fetch_resource():
                src = request.args.get('src')
                return jsonify(FetchService.get(src))

            @fetch_bp.route('/batch', methods=['POST'])
            @require_auth
            def fetch_batch():
                urls = request.json.get('urls', [])
                return jsonify(FetchService.get_many(urls))
        """),

        "api/exec_api.py": textwrap.dedent("""\
            from flask import Blueprint, request, jsonify
            from services.exec_service import ExecService

            exec_bp = Blueprint('exec', __name__)

            @exec_bp.route('/run', methods=['POST'])
            def run_script():
                # VULN: no auth + command injection via script param
                script = request.json.get('script', '')
                output = ExecService.run(script)
                return jsonify({'output': output})

            @exec_bp.route('/eval', methods=['POST'])
            def eval_code():
                # VULN: eval of user-supplied code
                code = request.json.get('code', '')
                result = ExecService.safe_eval(code)
                return jsonify({'result': result})
        """),

        "api/health.py": textwrap.dedent("""\
            from flask import Blueprint, jsonify

            health_bp = Blueprint('health', __name__)

            @health_bp.route('/', methods=['GET'])
            def health():
                return jsonify({'status': 'healthy'})

            @health_bp.route('/deep', methods=['GET'])
            def deep_health():
                return jsonify({'db': 'ok', 'cache': 'ok'})
        """),

        "api/users.py": textwrap.dedent("""\
            from flask import Blueprint, request, jsonify
            from middleware.auth import require_auth
            from services.user_service import UserService

            users_bp = Blueprint('users', __name__)

            @users_bp.route('/', methods=['GET'])
            @require_auth
            def list_users():
                return jsonify(UserService.get_all())

            @users_bp.route('/<int:uid>', methods=['GET'])
            @require_auth
            def get_user(uid):
                return jsonify(UserService.get_by_id(uid))
        """),

        "middleware/__init__.py": "",

        "middleware/auth.py": textwrap.dedent("""\
            from functools import wraps
            from flask import request, jsonify

            INTERNAL_HOSTS = {'localhost', '127.0.0.1', '0.0.0.0', '::1'}

            def require_auth(f):
                @wraps(f)
                def decorated(*args, **kwargs):
                    token = request.headers.get('Authorization', '')
                    if not token.startswith('Bearer '):
                        return jsonify({'error': 'unauthorized'}), 401
                    return f(*args, **kwargs)
                return decorated
        """),

        "services/__init__.py": "",

        "services/proxy_service.py": textwrap.dedent("""\
            import urllib.request

            class ProxyService:
                @staticmethod
                def fetch(url: str) -> str:
                    # VULN: no blocklist for internal IPs (SSRF)
                    with urllib.request.urlopen(url, timeout=5) as resp:
                        return resp.read().decode('utf-8', errors='replace')
        """),

        "services/fetch_service.py": textwrap.dedent("""\
            import urllib.request

            class FetchService:
                @staticmethod
                def get(src: str) -> dict:
                    with urllib.request.urlopen(src, timeout=5) as r:
                        return {'content': r.read().decode()}

                @staticmethod
                def get_many(urls: list) -> list:
                    return [FetchService.get(u) for u in urls]
        """),

        "services/exec_service.py": textwrap.dedent("""\
            import subprocess

            class ExecService:
                @staticmethod
                def run(script: str) -> str:
                    # VULN: shell=True with user input → RCE
                    result = subprocess.run(
                        script, shell=True, capture_output=True, text=True, timeout=10
                    )
                    return result.stdout + result.stderr

                @staticmethod
                def safe_eval(code: str):
                    # VULN: eval() of untrusted input
                    return eval(code)  # noqa: S307
        """),

        "services/user_service.py": textwrap.dedent("""\
            class UserService:
                _store = {1: {'id': 1, 'name': 'alice', 'role': 'admin'},
                          2: {'id': 2, 'name': 'bob',   'role': 'user'}}

                @classmethod
                def get_all(cls):
                    return list(cls._store.values())

                @classmethod
                def get_by_id(cls, uid):
                    return cls._store.get(uid)
        """),

        "config.py": textwrap.dedent("""\
            import os

            DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
            SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-do-not-use-in-prod')
            ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost').split(',')
        """),

        "utils/validators.py": textwrap.dedent("""\
            import re
            from urllib.parse import urlparse

            def is_safe_url(url: str) -> bool:
                \"\"\"Placeholder validator – not actually called anywhere (design gap).\"\"\"
                try:
                    parsed = urlparse(url)
                    return parsed.scheme in ('http', 'https')
                except Exception:
                    return False
        """),

        "utils/__init__.py": "",
    }
