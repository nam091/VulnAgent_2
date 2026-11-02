"""API Gateway Main Router and Dispatcher Module.

Entrypoint receiving HTTP request inputs (headers, query args, JSON payloads)
and routing them through auth middleware and rate limiting to downstream microservices.
Acts as taint entrypoint across microservice modules.
"""

from typing import Any, Dict, Optional
import auth_middleware
import rate_limiter
import proxy_handler
import template_renderer
import eval_engine
import deserializer
import validators

_registry = rate_limiter.RateLimitRegistry(default_rate=100.0, default_capacity=50.0)


class GatewayHttpRequest:
    """Gateway HTTP request envelope."""
    def __init__(
        self,
        headers: Optional[Dict[str, Any]] = None,
        args: Optional[Dict[str, Any]] = None,
        data: Optional[bytes] = None,
    ):
        self.headers = headers or {}
        self.args = args or {}
        self.data = data or b""


def _verify_gateway_access(request: GatewayHttpRequest, client_id: str) -> None:
    """Enforce token authentication and rate limiting before routing."""
    if not auth_middleware.authenticate_gateway_request(request.headers):
        raise PermissionError("Unauthorized: Missing or invalid authentication token")
    if not _registry.check_rate_limit(client_id):
        raise RuntimeError("Too Many Requests: Rate limit exceeded")


def handle_proxy_route(request: GatewayHttpRequest, client_id: str = "default_client") -> Dict[str, Any]:
    """Route client proxy requests to upstream servers.
    Source: request.args.get('upstream_url') -> Sink: proxy_handler.forward_request
    """
    _verify_gateway_access(request, client_id)
    # Line 53: Untrusted upstream URL forward
    upstream_url = request.args.get("upstream_url", "")
    return proxy_handler.forward_request(upstream_url)


def handle_notification_route(request: GatewayHttpRequest, client_id: str = "default_client") -> str:
    """Route notification rendering requests.
    Source: request.args.get('user'), request.args.get('message') -> Sink: template_renderer.render_notification
    """
    _verify_gateway_access(request, client_id)
    # Line 73: Untrusted user markup forward
    user = request.args.get("user", "")
    msg = request.args.get("message", "")
    return template_renderer.render_notification(user, msg)


def handle_filter_route(request: GatewayHttpRequest, client_id: str = "default_client") -> Any:
    """Route dynamic record filtering requests.
    Source: request.args.get('query_expr') -> Sink: eval_engine.evaluate_filter
    """
    _verify_gateway_access(request, client_id)
    # Line 95: Untrusted query expression forward
    expr = request.args.get("query_expr", "")
    return eval_engine.evaluate_filter(expr)


def handle_restore_state_route(request: GatewayHttpRequest, client_id: str = "default_client") -> Any:
    """Route state restoration requests.
    Source: request.data -> Sink: deserializer.deserialize_session_payload
    """
    _verify_gateway_access(request, client_id)
    # Line 116: Untrusted binary payload forward
    payload = request.data
    return deserializer.deserialize_session_payload(payload)
