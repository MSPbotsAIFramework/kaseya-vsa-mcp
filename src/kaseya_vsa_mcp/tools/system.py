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
"""Organizations and machine groups."""

from mcp.server.fastmcp import FastMCP

from ..api_client import VsaClient
from ._common import READ_ONLY, ClientFactory, ODataFilter, Skip, Top, fetch, run_tool


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def kaseya_vsa_list_organizations(top: Top = 250, filter: ODataFilter = None, skip: Skip = None) -> str:
        """List organizations: id, name, type, parent, contact details."""

        async def action(client: VsaClient) -> dict:
            return await fetch(client, "system/orgs", "organizations", top, skip, filter)

        return await run_tool("kaseya_vsa_list_organizations", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def kaseya_vsa_list_machine_groups(top: Top = 250, filter: ODataFilter = None, skip: Skip = None) -> str:
        """List machine groups (the organization -> group hierarchy agents belong to)."""

        async def action(client: VsaClient) -> dict:
            return await fetch(client, "system/machinegroups", "machine_groups", top, skip, filter)

        return await run_tool("kaseya_vsa_list_machine_groups", client_factory, action)
