# Copyright 2026 MSPbots.ai
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""FastMCP factory and the per-request credential middleware."""

import contextvars
import re
import uuid
from collections.abc import Callable
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .api_client import VsaClient, VsaCredentials, api_base
from .config import Settings

HEADER_URL = "X-Kaseya-VSA-Tenant-Url"
HEADER_USERNAME = "X-Kaseya-VSA-Username"
HEADER_PASSWORD = "X-Kaseya-VSA-Password"
HEADER_K1_TOKEN = "X-Kaseya-VSA-K1-Token"
REQUIRED_HEADERS = [HEADER_URL, f"{HEADER_USERNAME} + {HEADER_PASSWORD} or {HEADER_K1_TOKEN}"]

_PLACEHOLDER = re.compile(r"^\$\{.*\}$")

# Per-request isolation: the middleware sets these for the duration of one
# HTTP request and resets them in `finally`. The session cache is keyed by a
# hash of the full credential set.
_credentials_var: contextvars.ContextVar[VsaCredentials | None] = contextvars.ContextVar("vsa_credentials", default=None)
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("vsa_request_id", default="-")

INSTRUCTIONS = (
    "Kaseya VSA is an RMM: agents run on the MSP's managed endpoints, grouped "
    "into organizations and machine groups.\n"
    "Usage:\n"
    "- Find a machine: kaseya_vsa_list_agents(filter=\"startswith(AgentName,'PC')\") "
    "-> kaseya_vsa_get_agent(agentId = AgentId).\n"
    "- Inventory: kaseya_vsa_get_software_inventory / _get_hardware_inventory; "
    "patches: kaseya_vsa_get_patch_status.\n"
    "- Problems: kaseya_vsa_list_alarms (open by default), kaseya_vsa_list_tickets.\n"
    "- Lists take an OData filter, top (max 100) and skip.\n"
    "kaseya_vsa_deploy_patches_now and kaseya_vsa_run_procedure change the "
    "endpoint: they need confirm: true after the user approved that exact "
    "action. Agent procedures must be approved in VSA before they can run."
)


def get_client_from_context() -> VsaClient | None:
    """The client for the current request, or None outside a request."""
    credentials = _credentials_var.get()
    if credentials is None:
        return None
    return VsaClient(credentials)


def _clean(value: str | None) -> str | None:
    text = (value or "").strip()
    if not text or _PLACEHOLDER.match(text):
        return None
    return text


def normalize_url(value: str) -> str | None:
    """A https VSA server URL (scheme added when missing) as its REST base; None when invalid."""
    text = value.strip()
    if "://" not in text:
        text = f"https://{text}"
    parsed = urlparse(text)
    if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
        return None
    return api_base(f"https://{parsed.netloc}{parsed.path}")


def _error(scope: Scope, receive: Receive, send: Send, status: int, error: str, message: str):
    return JSONResponse({"error": error, "message": message, "required_headers": REQUIRED_HEADERS}, status_code=status)(
        scope, receive, send
    )


class GatewayCredentialsMiddleware:
    """Reads the VSA server URL and credentials on /mcp requests into the request context."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        url = _clean(request.headers.get(HEADER_URL))
        username = _clean(request.headers.get(HEADER_USERNAME))
        password = _clean(request.headers.get(HEADER_PASSWORD))
        k1_token = _clean(request.headers.get(HEADER_K1_TOKEN))
        has_login = bool(username and password)
        if not url or not (has_login or k1_token):
            missing = ([HEADER_URL] if not url else []) + ([REQUIRED_HEADERS[1]] if not (has_login or k1_token) else [])
            await _error(scope, receive, send, 401, "Missing credentials", f"Missing header(s): {', '.join(missing)}")
            return
        base = normalize_url(url)
        if base is None:
            await _error(scope, receive, send, 400, "Invalid credentials", f"{HEADER_URL} must be an https URL, e.g. https://vsa.example.com")
            return

        # Supply either username + password or the Kaseya One token; the login wins when both arrive.
        credentials = VsaCredentials(base, username, password, None) if has_login else VsaCredentials(base, k1_token=k1_token)
        request_id = (request.headers.get("x-request-id") or "").strip()[:64] or uuid.uuid4().hex[:12]
        creds_token = _credentials_var.set(credentials)
        rid_token = request_id_var.set(request_id)
        try:
            await self.app(scope, receive, send)
        finally:
            _credentials_var.reset(creds_token)
            request_id_var.reset(rid_token)


def create_mcp_server(settings: Settings | None = None) -> FastMCP:
    """Build the FastMCP server and register every tool."""
    mcp = FastMCP(
        name="kaseya-vsa-mcp",
        instructions=INSTRUCTIONS,
        # The service sits behind the gateway, so Host is never localhost;
        # DNS-rebinding protection would reject those requests with 421.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
    )

    client_factory: Callable[[], VsaClient | None] = get_client_from_context

    from .tools import agents, automation, monitoring, system

    for module in (agents, automation, monitoring, system):
        module.register(mcp, client_factory)

    return mcp
