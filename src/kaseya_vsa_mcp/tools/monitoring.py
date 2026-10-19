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
"""Alarms and tickets."""

from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import VsaClient, VsaError
from ._common import READ_ONLY, ClientFactory, ODataFilter, Skip, Top, fetch, run_tool


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def kaseya_vsa_list_alarms(
        filter: ODataFilter = None,
        top: Top = 50,
        include_closed: Annotated[bool, Field(description="Also return closed alarms (default: open alarms only).")] = False,
        skip: Skip = None,
    ) -> str:
        """List alarms (open by default): agent, alarm type, subject, time, state."""

        async def action(client: VsaClient) -> dict:
            flag = "true" if include_closed else "false"
            return await fetch(client, f"assetmgmt/alarms/{flag}", "alarms", top, skip, filter)

        return await run_tool("kaseya_vsa_list_alarms", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def kaseya_vsa_list_tickets(
        filter: ODataFilter = None,
        top: Top = 50,
        service_desk_id: Annotated[str | None, Field(description="Read this Service Desk's tickets instead of the Ticketing module's.")] = None,
        skip: Skip = None,
    ) -> str:
        """List tickets from the Ticketing module, or from one Service Desk when service_desk_id is given."""

        async def action(client: VsaClient) -> dict:
            path = f"automation/servicedesks/{service_desk_id}/tickets" if service_desk_id else "automation/tickets"
            try:
                return await fetch(client, path, "tickets", top, skip, filter)
            except VsaError as e:
                if e.status_code != 404:
                    raise
                module = "Service Desk" if service_desk_id else "Ticketing"
                return {"tickets": [], "count": 0, "message": f"The {module} module does not appear to be enabled on this VSA server (HTTP 404)."}

        return await run_tool("kaseya_vsa_list_tickets", client_factory, action)
