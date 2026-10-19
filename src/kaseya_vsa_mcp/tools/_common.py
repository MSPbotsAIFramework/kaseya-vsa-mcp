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
"""Shared argument types, OData paging helpers and the error-handling wrapper."""

import logging
import time
from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped, error_envelope
from ..api_client import VsaClient, VsaError
from ..config import MAX_PAGE_SIZE

logger = logging.getLogger("kaseya_vsa_mcp.tools")

ClientFactory = Callable[[], VsaClient | None]

READ_ONLY = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True)

NOT_CONFIGURED = error_envelope(
    "not_configured",
    "Kaseya VSA credentials are missing for this request (X-Kaseya-VSA-Tenant-Url plus "
    "X-Kaseya-VSA-Username + X-Kaseya-VSA-Password or X-Kaseya-VSA-K1-Token).",
    False,
)

AgentId = Annotated[str, Field(description="Agent id (AgentId from kaseya_vsa_list_agents).", min_length=1)]
ODataFilter = Annotated[str | None, Field(description="OData $filter, e.g. \"startswith(AgentName,'PC')\".")]
Confirm = Annotated[bool | None, Field(description="Must be true, set only after the user approved this exact action.")]


def compact(values: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in values.items() if v is not None and v != ""}


MAX_TOTAL = 500
MAX_TOP = 200
Top = Annotated[int, Field(description=f"Records to return (default 50, max {MAX_TOP}; fetched 100 per request).", ge=1, le=MAX_TOP)]
# For tools without skip: one call is all the caller gets, so they keep the larger maximum.
SingleCallTop = Annotated[int, Field(description=f"Records to return (default 50, up to {MAX_TOTAL}; fetched 100 per request).", ge=1)]
Skip = Annotated[int | None, Field(description="Records to skip.", ge=0)]


def result(payload: Any) -> Any:
    """The `Result` member of VSA's {Result, ResponseCode, Status, Error} envelope."""
    if isinstance(payload, dict) and "Result" in payload:
        return payload["Result"]
    return payload


def rows_of(payload: Any) -> list:
    value = result(payload)
    return value if isinstance(value, list) else ([] if value is None else [value])


async def fetch(client: VsaClient, path: str, key: str, top: int, skip: int | None = None, filter: str | None = None) -> dict:
    """GET an OData collection, following $skip until `top` records (or the end) are read."""
    wanted = min(max(top, 1), MAX_TOTAL)
    offset = skip or 0
    rows: list = []
    total = None
    while len(rows) < wanted:
        size = min(MAX_PAGE_SIZE, wanted - len(rows))
        payload = await client.get(path, compact({"$top": size, "$skip": offset or None, "$filter": filter}))
        page = rows_of(payload)
        if isinstance(payload, dict) and payload.get("TotalRecords") is not None:
            total = payload.get("TotalRecords")
        rows += page
        offset += len(page)
        if len(page) < size or (total is not None and offset >= total):
            break
    more = (total is not None and offset < total) or (total is None and len(rows) >= wanted)
    return compact({key: rows, "count": len(rows), "total": total, "has_more": more, "next_skip": offset if more else None})


def not_confirmed(action: str) -> dict:
    return {
        "done": False,
        "action": action,
        "message": "Not done. Describe this action to the user and call again with confirm: true only after they approve it.",
    }


async def run_tool(
    name: str,
    client_factory: ClientFactory,
    action: Callable[[VsaClient], Awaitable[Any]],
) -> str:
    """Resolve the caller's client, run ``action``, and always return a string.

    Errors never escape as exceptions: they become the standard error envelope.
    """
    client = client_factory()
    if client is None:
        return NOT_CONFIGURED
    started = time.monotonic()
    try:
        value = await action(client)
    except VsaError as e:
        logger.info("tool=%s outcome=error status=%s ms=%d", name, e.status_code, _ms(started))
        return e.to_envelope()
    except ValueError as e:
        logger.info("tool=%s outcome=invalid_argument ms=%d", name, _ms(started))
        return error_envelope("invalid_argument", str(e), False)
    except Exception as e:  # noqa: BLE001 - tools must never raise
        logger.warning("tool=%s outcome=unexpected error=%s ms=%d", name, type(e).__name__, _ms(started))
        return error_envelope("upstream_error", f"Unexpected error: {type(e).__name__}", True)
    logger.info("tool=%s outcome=ok ms=%d", name, _ms(started))
    if value is None:
        value = {"done": True}
    return value if isinstance(value, str) else dump_json_capped(value)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
