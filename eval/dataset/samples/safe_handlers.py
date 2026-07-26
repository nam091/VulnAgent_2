"""Evaluation sample with no vulnerabilities.

Deliberately exercises every pattern that trips naive detection - raw SQL,
subprocess, filesystem reads, password handling, templating - while doing
each one correctly. Findings reported here are false positives, which makes
this the file that actually measures precision.
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
import subprocess
from pathlib import Path

from flask import Flask, abort, render_template, request

app = Flask(__name__)

UPLOAD_ROOT = Path(__file__).resolve().parent / "uploads"
ALLOWED_COMMANDS = {"uptime": ["uptime"], "diskfree": ["df", "-h"]}


def get_db() -> sqlite3.Connection:
    return sqlite3.connect("database.db")


@app.route('/user/<username>')
def user_profile(username: str):
    db = get_db()
    cursor = db.cursor()
    # Parameterised: the driver escapes the value, not string formatting.
    cursor.execute("SELECT id, display_name FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if user is None:
        abort(404)
    # Jinja autoescaping handles the untrusted values.
    return render_template('profile.html', username=username, user=user)


@app.route('/download')
def download_file():
    requested = request.args.get('filename', '')
    # Resolve first, then confirm containment: a traversal attempt resolves
    # outside UPLOAD_ROOT and is rejected before anything is opened.
    candidate = (UPLOAD_ROOT / requested).resolve()
    if not candidate.is_file() or UPLOAD_ROOT.resolve() not in candidate.parents:
        abort(404)
    return candidate.read_text(encoding='utf-8')


@app.route('/diagnostics')
def diagnostics():
    name = request.args.get('command', '')
    argv = ALLOWED_COMMANDS.get(name)
    if argv is None:
        abort(400)
    # Fixed argument vector from an allow-list; no shell, no interpolation.
    result = subprocess.run(argv, capture_output=True, text=True, timeout=5, shell=False)
    return {'output': result.stdout}


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    expected_user = os.environ['ADMIN_USER']
    expected_hash = bytes.fromhex(os.environ['ADMIN_PASSWORD_SHA256'])
    salt = bytes.fromhex(os.environ['ADMIN_PASSWORD_SALT'])

    derived = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000)
    # Constant-time comparison on both factors.
    user_ok = hmac.compare_digest(username.encode(), expected_user.encode())
    pass_ok = hmac.compare_digest(derived, expected_hash)
    if not (user_ok and pass_ok):
        abort(401)
    return {'session': secrets.token_urlsafe(32)}


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=False)
