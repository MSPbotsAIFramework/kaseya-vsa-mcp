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
"""Credential middleware: 401 / 400 on bad headers, URL normalisation, isolation."""

import asyncio

import pytest
from starlette.testclient import TestClient

from kaseya_vsa_mcp.__main__ import build_http_app
from kaseya_vsa_mcp.server import GatewayCredentialsMiddleware, _credentials_var, create_mcp_server, get_client_from_context, normalize_url

MCP_HEADERS = {"Accept": "application/json, text/event-stream"}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
URL = {"X-Kaseya-VSA-Tenant-Url": "https://vsa.example.com"}
LOGIN = {"X-Kaseya-VSA-Username": "api-user", "X-Kaseya-VSA-Password": "pat-123"}


def _client() -> TestClient:
    return TestClient(build_http_app(create_mcp_server()))


def test_health_is_local():
    with _client() as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.parametrize(
    "headers",
    [{}, LOGIN, URL, URL | {"X-Kaseya-VSA-Username": "api-user"}, URL | {"X-Kaseya-VSA-K1-Token": "${K1}"}],
)
def test_missing_headers_return_401(headers):
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | headers)
    assert resp.status_code == 401


def test_plain_http_returns_400():
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | LOGIN | {"X-Kaseya-VSA-Tenant-Url": "http://vsa.example.com"})
    assert resp.status_code == 400


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://vsa.example.com", "https://vsa.example.com/api/v1.0"),
        ("vsa.example.com/", "https://vsa.example.com/api/v1.0"),
        ("https://vsa.example.com/api/v1.0", "https://vsa.example.com/api/v1.0"),
        ("https://vsa.example.com/api/v1.0/", "https://vsa.example.com/api/v1.0"),
        ("https://vsa.example.com:8443/kaseya", "https://vsa.example.com:8443/kaseya/api/v1.0"),
        ("http://vsa.example.com", None),
        ("https://vsa.example.com/?x=1", None),
    ],
)
def test_normalize_url(value, expected):
    assert normalize_url(value) == expected


def test_tools_list_over_http():
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | URL | LOGIN)
    assert resp.status_code == 200
    for name in ("kaseya_vsa_list_agents", "kaseya_vsa_run_procedure", "kaseya_vsa_list_machine_groups"):
        assert name in resp.text


async def _receive():
    return {"type": "http.request", "body": b"", "more_body": False}


async def _send(_message):
    return None


def _run_middleware(headers: dict[str, str]) -> dict:
    seen: dict = {}

    async def app(scope, receive, send):
        seen["credentials"] = _credentials_var.get()
        seen["client"] = get_client_from_context()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    asyncio.run(GatewayCredentialsMiddleware(app)({"type": "http", "path": "/mcp", "headers": raw}, _receive, _send))
    return seen


def test_login_wins_over_k1_and_context_is_reset():
    seen = _run_middleware(URL | LOGIN | {"X-Kaseya-VSA-K1-Token": "k1"})
    creds = seen["credentials"]
    assert (creds.username, creds.password, creds.k1_token) == ("api-user", "pat-123", None)
    assert seen["client"].base_url == "https://vsa.example.com/api/v1.0"
    assert _credentials_var.get() is None


def test_k1_only():
    creds = _run_middleware(URL | {"X-Kaseya-VSA-K1-Token": " k1-tok "})["credentials"]
    assert creds.k1_token == "k1-tok" and creds.username is None


def test_concurrent_requests_do_not_share_credentials():
    observed: list[tuple[str, str]] = []

    async def app(scope, receive, send):
        before = _credentials_var.get().username
        await asyncio.sleep(0.01)
        observed.append((before, _credentials_var.get().username))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = GatewayCredentialsMiddleware(app)

    def scope(user: bytes) -> dict:
        headers = [(b"x-kaseya-vsa-tenant-url", b"https://vsa.example.com"), (b"x-kaseya-vsa-username", user), (b"x-kaseya-vsa-password", b"p")]
        return {"type": "http", "path": "/mcp", "headers": headers}

    async def both():
        await asyncio.gather(middleware(scope(b"tenant-a"), _receive, _send), middleware(scope(b"tenant-b"), _receive, _send))

    asyncio.run(both())
    assert sorted(observed) == [("tenant-a", "tenant-a"), ("tenant-b", "tenant-b")]


def test_credentials_repr_hides_secrets():
    creds = _run_middleware(URL | {"X-Kaseya-VSA-Username": "u", "X-Kaseya-VSA-Password": "very-secret-pass"})["credentials"]
    assert "very-secret-pass" not in repr(creds)
