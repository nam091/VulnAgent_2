"""Dynamic Template Rendering and Notification Service.

Microservice handler generating HTML notifications and banner markup.
Contains Cross-File Cross-Site Scripting sink (CWE-79).
"""

from typing import Any, Dict, Optional
from flask import Flask, render_template_string
import validators

_app = Flask("apigateway_template_renderer")


def render_notification(user: str, message: str, level: str = "info") -> str:
    """Render dynamic HTML notification containing user-provided markup.

    VULNERABILITY: Cross-File Cross-Site Scripting (CWE-79).
    The user and message parameters originate from client HTTP requests in gateway_router.py
    and are interpolated directly into an unescaped Jinja2 template string passed to
    render_template_string().
    """
    template = f"""<div class='notification {level}'>
        <h3>Notification for {user}</h3>
        <p>{message}</p>
    </div>"""
    with _app.app_context():
        # Line 28: Unsanitized template string rendering without HTML escaping (Sink)
        return render_template_string(template)


def render_notification_safe(user: str, message: str, level: str = "info") -> str:
    """Safe counterpart escaping HTML metacharacters before rendering."""
    safe_user = validators.sanitize_html(user)
    safe_message = validators.sanitize_html(message)
    template = """<div class='notification {{ level }}'>
        <h3>Notification for {{ user | safe }}</h3>
        <p>{{ message | safe }}</p>
    </div>"""
    with _app.app_context():
        return render_template_string(template, user=safe_user, message=safe_message, level=level)
