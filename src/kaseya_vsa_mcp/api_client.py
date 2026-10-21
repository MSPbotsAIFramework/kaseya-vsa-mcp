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
"""Async client for the Kaseya VSA REST API (v1.0) with its session-token sign-in."""

import asyncio
import base64
import hashlib
import logging
import secrets
import string
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from http.cookiejar import CookieJar, DefaultCookiePolicy
from typing import Any

import httpx

from ._json import error_envelope
from .config import API_PATH

logger = logging.getLogger("kaseya_vsa_mcp.api")

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
_MAX_RETRIES = 2
_MAX_BACKOFF_SECONDS = 20.0
# Whole-call budget including retries; the gateway times a tool call out at 120s.
_CALL_BUDGET_SECONDS = 100.0
_DEFAULT_SESSION_SECONDS = 15 * 60.0
_REFRESH_MARGIN_SECONDS = 60.0

# One connection pool for the process. It never holds credentials: the
# Authorization header is built per request from the caller's own session.
_shared_http_client: httpx.AsyncClient | None = None

# Session tokens keyed by a SHA-256 of the full credential set (secret included),
# so a token is only reused by a caller holding exactly the same credentials.
_session_cache: dict[str, tuple[str, float]] = {}


class _RejectAllCookies(DefaultCookiePolicy):
    """Never store or send a cookie: the HTTP client is shared by every tenant."""

    def set_ok(self, cookie, request) -> bool:  # noqa: ANN001 - stdlib signature
        return False

    def return_ok(self, cookie, request) -> bool:  # noqa: ANN001 - stdlib signature
        return False


def _no_cookies() -> CookieJar:
    # A plain CookieJar: httpx uses it as is (an httpx.Cookies would be copied into a default jar).
    return CookieJar(policy=_RejectAllCookies())


def _get_shared_http_client() -> httpx.AsyncClient:
    global _shared_http_client
    if _shared_http_client is None:
        _shared_http_client = httpx.AsyncClient(cookies=_no_cookies(), timeout=_TIMEOUT, follow_redirects=True)
    return _shared_http_client


# status_code -> (error code, retryable). 0 means no HTTP response at all
# (connection error or timeout).
_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("invalid_argument", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    404: ("not_found", False),
    409: ("invalid_argument", False),
    422: ("invalid_argument", False),
    429: ("rate_limited", True),
}


def classify_status(status_code: int) -> tuple[str, bool]:
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    if status_code >= 500:
        return "upstream_error", True
    if status_code >= 400:
        return "invalid_argument", False
    return "upstream_error", True


class VsaError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"Kaseya VSA API error {status_code}: {message}")

    def to_envelope(self) -> str:
        code, retryable = classify_status(self.status_code)
        return error_envelope(code, self.message, retryable)


@dataclass(frozen=True)
class VsaCredentials:
    base_url: str  # https://vsa.example.com/api/v1.0
    username: str | None = None
    password: str | None = None  # a personal access token or the account password
    k1_token: str | None = None

    def __repr__(self) -> str:  # never leak secrets into logs or tracebacks
        return f"VsaCredentials(base_url={self.base_url!r}, username={self.username!r}, secrets=<redacted>)"

    def cache_key(self) -> str:
        raw = "\n".join((self.base_url, self.username or "", self.password or "", self.k1_token or ""))
        return hashlib.sha256(raw.encode()).hexdigest()


def legacy_auth_header(username: str, password: str, nonce: str) -> str:
    """The hashed sign-in header older VSA servers accept instead of plain Basic credentials."""
    sha256 = hashlib.sha256((hashlib.sha256((password + username).encode()).hexdigest() + nonce).encode()).hexdigest()
    sha1 = hashlib.sha1((hashlib.sha1((password + username).encode()).hexdigest() + nonce).encode()).hexdigest()
    return f"Basic user={username},pass2={sha256},pass1={sha1},rand2={nonce}"


def _nonce() -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))


def _session_seconds(result: dict) -> float:
    expiry = result.get("SessionExpiration")
    if isinstance(expiry, str) and expiry:
        try:
            parsed = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return max(0.0, (parsed - datetime.now(UTC)).total_seconds())
        except ValueError:
            pass
    return _DEFAULT_SESSION_SECONDS


class VsaClient:
    """Thin wrapper over one VSA server's REST API for one caller's credentials."""

    def __init__(self, credentials: VsaCredentials, http_client: httpx.AsyncClient | None = None):
        self._credentials = credentials
        self._http = http_client
        self.base_url = credentials.base_url

    # ---- auth -----------------------------------------------------------------

    async def _sign_in(self, authorization: str, path: str) -> str | None:
        http = self._http or _get_shared_http_client()
        try:
            resp = await http.get(f"{self.base_url}/{path}", headers={"Authorization": authorization, "Accept": "application/json"})
        except httpx.TimeoutException as e:
            raise VsaError(0, "Timed out signing in to Kaseya VSA") from e
        except httpx.RequestError as e:
            raise VsaError(0, f"Network error signing in to Kaseya VSA: {type(e).__name__}") from e
        logger.info("vsa_auth path=%s status=%s", path, resp.status_code)
        if resp.status_code >= 500:
            raise VsaError(resp.status_code, f"Kaseya VSA returned HTTP {resp.status_code} while signing in")
        try:
            payload = resp.json()
        except ValueError:
            payload = None
        result = payload.get("Result") if isinstance(payload, dict) else None
        if not isinstance(result, dict):
            return None
        token = result.get("Token") or result.get("ApiToken")
        if resp.status_code >= 400 or not token:
            return None
        _session_cache[self._credentials.cache_key()] = (token, time.monotonic() + _session_seconds(result))
        return token

    async def _token(self, force_refresh: bool = False) -> str:
        cached = _session_cache.get(self._credentials.cache_key())
        if cached and not force_refresh and cached[1] - _REFRESH_MARGIN_SECONDS > time.monotonic():
            return cached[0]
        creds = self._credentials
        if creds.k1_token:
            token = await self._sign_in(f"Bearer {creds.k1_token}", "auth/sso")
            if token:
                return token
            raise VsaError(401, "Kaseya VSA did not accept the Kaseya One token")
        assert creds.username and creds.password
        basic = base64.b64encode(f"{creds.username}:{creds.password}".encode()).decode()
        token = await self._sign_in(f"Basic {basic}", "auth")
        if token:
            return token
        # Older servers only accept the hashed form of the same credentials.
        token = await self._sign_in(legacy_auth_header(creds.username, creds.password, _nonce()), "auth")
        if token:
            return token
        raise VsaError(401, "Kaseya VSA rejected the user name and password / access token")

    # ---- requests ---------------------------------------------------------------

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self.request("GET", path, params=params)

    async def put(self, path: str, body: Any = None) -> Any:
        return await self.request("PUT", path, body=body)

    async def request(self, method: str, path: str, params: dict[str, Any] | None = None, body: Any = None) -> Any:
        http = self._http or _get_shared_http_client()
        url = f"{self.base_url}/{path.lstrip('/')}"
        query = {k: v for k, v in (params or {}).items() if v is not None}
        token = await self._token()
        refreshed = False
        started = time.monotonic()
        attempt = 0
        while True:
            t0 = time.monotonic()
            resp: httpx.Response | None = None
            error: VsaError | None = None
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            try:
                kwargs: dict[str, Any] = {"params": query, "headers": headers}
                if body is not None:
                    kwargs["json"] = body
                resp = await http.request(method, url, **kwargs)
                status = resp.status_code
            except httpx.TimeoutException:
                status, error = 0, VsaError(0, f"Timed out calling Kaseya VSA ({method} {path})")
            except httpx.RequestError as e:
                status, error = 0, VsaError(0, f"Network error calling Kaseya VSA ({method} {path}): {type(e).__name__}")

            logger.info("vsa_api method=%s path=%s status=%s ms=%d attempt=%d", method, path, status, (time.monotonic() - t0) * 1000, attempt)

            # Sessions expire after inactivity: sign in again once.
            if status == 401 and not refreshed:
                refreshed = True
                token = await self._token(force_refresh=True)
                continue

            # 429 is refused before processing, so any method may retry it; other
            # failures are retried only for reads, so a write never runs twice.
            retryable = status == 429 or (method == "GET" and (status == 0 or status >= 500))
            if retryable and attempt < _MAX_RETRIES:
                delay = _retry_delay(resp, attempt)
                if time.monotonic() - started + delay < _CALL_BUDGET_SECONDS:
                    attempt += 1
                    await asyncio.sleep(delay)
                    continue
            if error is not None:
                raise error
            assert resp is not None
            if resp.status_code >= 400:
                raise VsaError(resp.status_code, _error_message(resp, path))
            if not resp.content or not resp.content.strip():
                return None
            try:
                payload = resp.json()
            except ValueError:
                return {"raw_response": resp.text[:2000]}
            # VSA wraps responses as {Result, ResponseCode, Status, Error[, TotalRecords]}.
            if isinstance(payload, dict) and str(payload.get("ResponseCode", "0")) not in ("0", "None") and payload.get("Error"):
                raise VsaError(400, f"Kaseya VSA rejected the request for {path}: {str(payload.get('Error'))[:500]}")
            return payload


def api_base(url: str) -> str:
    """Normalise a VSA server URL to its REST base, e.g. https://vsa.example.com/api/v1.0."""
    trimmed = url.strip().rstrip("/")
    if trimmed.lower().endswith(API_PATH):
        trimmed = trimmed[: -len(API_PATH)]
    return f"{trimmed}{API_PATH}"


def _retry_delay(resp: httpx.Response | None, attempt: int) -> float:
    if resp is not None:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return max(0.0, min(float(retry_after), _MAX_BACKOFF_SECONDS))
            except ValueError:
                pass
    return min(float(2**attempt), _MAX_BACKOFF_SECONDS)


def _error_message(resp: httpx.Response, path: str) -> str:
    fallback = f"Kaseya VSA returned HTTP {resp.status_code} for {path}"
    try:
        payload = resp.json()
    except ValueError:
        text = resp.text.strip()
        if text.lower().startswith("<"):
            return fallback  # an HTML error page, not useful to the agent
        return f"{fallback}: {text[:300]}" if text else fallback
    if isinstance(payload, dict):
        message = payload.get("Error") or payload.get("Message") or payload.get("message")
        if message:
            return f"{fallback}: {str(message)[:500]}"
    return fallback
