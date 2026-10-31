"""Test suite for Microservice / API Gateway benchmark dataset."""

import base64
import json
import pickle
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parent.parent
VERIFY_SCRIPT = ROOT / "eval" / "datasets" / "apigateway_micro" / "verify_dataset.py"
SAMPLES_DIR = ROOT / "eval" / "datasets" / "apigateway_micro" / "samples"

# Add samples directory to sys.path so we can import and test the modules directly
if str(SAMPLES_DIR) not in sys.path:
    sys.path.insert(0, str(SAMPLES_DIR))

import auth_middleware
import crypto_utils
import deserializer
import eval_engine
import gateway_router
import proxy_handler
import rate_limiter
import template_renderer
import validators


def test_apigateway_micro_verification_script():
    """Execute the dataset verification script and assert exit code 0."""
    assert VERIFY_SCRIPT.is_file(), f"Verification script not found at {VERIFY_SCRIPT}"
    result = subprocess.run(
        [sys.executable, str(VERIFY_SCRIPT)],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0, f"Verification failed:\n{result.stderr}\n{result.stdout}"
    assert "ALL VERIFICATIONS PASSED" in result.stdout


def test_validators_module():
    """Test URL scheme and domain whitelist validators."""
    # Scheme validation
    assert validators.is_valid_url_scheme("https://api.internal.corp/data") is True
    assert validators.is_valid_url_scheme("http://service.internal.corp") is True
    assert validators.is_valid_url_scheme("file:///etc/passwd") is False
    assert validators.is_valid_url_scheme("gopher://127.0.0.1:6379") is False

    # Domain whitelisting
    assert validators.is_whitelisted_domain("https://api.internal.corp/status") is True
    assert validators.is_whitelisted_domain("https://sub.partner.api.com/v1") is True
    assert validators.is_whitelisted_domain("http://169.254.169.254/latest/meta-data") is False
    assert validators.is_whitelisted_domain("http://localhost:8000") is False
    assert validators.is_whitelisted_domain("https://attacker.evil.com") is False

    # Combined upstream validation
    assert validators.validate_upstream_url("https://api.internal.corp/v1") is True
    assert validators.validate_upstream_url("file:///proc/version") is False
    assert validators.validate_upstream_url("http://169.254.169.254/secret") is False

    # HTML sanitization
    assert validators.sanitize_html("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"


def test_crypto_utils_module():
    """Test HMAC-SHA256 signatures, verification, and token generation."""
    secret = "my-secret-key-12345"
    message = '{"action":"sync_state","user_id":42}'

    sig = crypto_utils.generate_hmac_signature(secret, message)
    assert isinstance(sig, str) and len(sig) == 64

    # Verify signature passes for valid match
    assert crypto_utils.verify_hmac_signature(secret, message, sig) is True

    # Verify signature fails on tampering
    assert crypto_utils.verify_hmac_signature(secret, message + "tampered", sig) is False
    assert crypto_utils.verify_hmac_signature("wrong-key", message, sig) is False

    # Secure token generation
    token = crypto_utils.generate_secure_token(16)
    assert len(token) == 32  # 16 bytes = 32 hex chars


def test_rate_limiter_module():
    """Test token bucket rate limiting backed by time.monotonic()."""
    limiter = rate_limiter.TokenBucketRateLimiter(rate=10.0, capacity=2.0)

    # First two tokens should succeed
    assert limiter.acquire(1.0) is True
    assert limiter.acquire(1.0) is True

    # Third token exceeds immediate capacity
    assert limiter.acquire(1.0) is False

    # Registry check
    registry = rate_limiter.RateLimitRegistry(default_rate=5.0, default_capacity=1.0)
    assert registry.check_rate_limit("client_A") is True
    assert registry.check_rate_limit("client_A") is False
    # Separate client has independent bucket
    assert registry.check_rate_limit("client_B") is True


def test_auth_middleware_module():
    """Test token extraction and authentication verification."""
    headers = {"Authorization": "Bearer valid-gateway-secret-token"}
    token = auth_middleware.extract_bearer_token(headers)
    assert token == "valid-gateway-secret-token"

    assert auth_middleware.verify_auth_token(token) is True
    assert auth_middleware.verify_auth_token("invalid-token") is False

    assert auth_middleware.authenticate_gateway_request(headers) is True
    assert auth_middleware.authenticate_gateway_request({}) is False


def test_proxy_handler_module():
    """Test proxy handler forwarding and safe counterpart."""
    # Test safe forward blocks unauthorized domain
    with pytest.raises(ValueError, match="Upstream URL rejected"):
        proxy_handler.forward_request_safe("http://169.254.169.254/latest")

    # Test forward with mocked requests
    mock_resp = MagicMock(status_code=200, headers={"Content-Type": "application/json"}, text='{"ok": true}')
    with patch("requests.get", return_value=mock_resp) as mock_get:
        res = proxy_handler.forward_request("https://target.corp/api")
        mock_get.assert_called_once_with("https://target.corp/api", params=None, timeout=5)
        assert res["status_code"] == 200
        assert res["body"] == '{"ok": true}'


def test_template_renderer_module():
    """Test template notification rendering and HTML escaping."""
    raw = template_renderer.render_notification("Alice", "Hello World!", "info")
    assert "Notification for Alice" in raw
    assert "<p>Hello World!</p>" in raw

    # Safe render escapes harmful markup
    safe = template_renderer.render_notification_safe("<script>alert(1)</script>", "<b>bold</b>")
    assert "<script>" not in safe
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in safe
    assert "&lt;b&gt;bold&lt;/b&gt;" in safe


def test_eval_engine_module():
    """Test dynamic query evaluation and safe record matching."""
    res = eval_engine.evaluate_filter("10 + 20")
    assert res == 30

    records = [
        {"name": "Alice", "role": "admin"},
        {"name": "Bob", "role": "guest"},
    ]
    # Safe matching
    assert eval_engine.evaluate_filter_safe("role", "admin", records[0]) is True
    assert eval_engine.evaluate_filter_safe("role", "admin", records[1]) is False


def test_deserializer_module():
    """Test binary session deserialization and safe JSON counterpart."""
    data = {"user": "Alice", "session_id": "xyz987"}
    pickled = pickle.dumps(data)

    restored = deserializer.deserialize_session_payload(pickled)
    assert restored == data

    # Base64 deserialization
    b64_str = base64.b64encode(pickled).decode("ascii")
    assert deserializer.deserialize_from_base64(b64_str) == data

    # Safe JSON counterpart
    json_str = json.dumps(data)
    assert deserializer.deserialize_session_safe(json_str) == data


def test_gateway_router_flow():
    """Test full Gateway Router request lifecycle."""
    auth_headers = {"Authorization": "Bearer valid-gateway-secret-token"}

    # 1. Proxy routing
    mock_resp = MagicMock(status_code=200, headers={}, text="upstream response")
    with patch("requests.get", return_value=mock_resp):
        req_proxy = gateway_router.GatewayHttpRequest(
            headers=auth_headers,
            args={"upstream_url": "https://api.internal.corp/status"},
        )
        resp = gateway_router.handle_proxy_route(req_proxy, client_id="test_client_proxy")
        assert resp["body"] == "upstream response"

    # 2. Notification routing
    req_notif = gateway_router.GatewayHttpRequest(
        headers=auth_headers,
        args={"user": "Dave", "message": "Your task finished"},
    )
    rendered = gateway_router.handle_notification_route(req_notif, client_id="test_client_notif")
    assert "Dave" in rendered

    # 3. Filter query routing
    req_filter = gateway_router.GatewayHttpRequest(
        headers=auth_headers,
        args={"query_expr": "100 * 2"},
    )
    val = gateway_router.handle_filter_route(req_filter, client_id="test_client_filter")
    assert val == 200

    # 4. State restore routing
    payload = pickle.dumps({"counter": 42})
    req_restore = gateway_router.GatewayHttpRequest(
        headers=auth_headers,
        data=payload,
    )
    state = gateway_router.handle_restore_state_route(req_restore, client_id="test_client_restore")
    assert state == {"counter": 42}

    # 5. Unauthorized access check
    unauth_req = gateway_router.GatewayHttpRequest(headers={})
    with pytest.raises(PermissionError, match="Unauthorized"):
        gateway_router.handle_proxy_route(unauth_req)
