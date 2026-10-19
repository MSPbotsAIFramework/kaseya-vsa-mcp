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
"""Agents (managed endpoints), their audit inventory and patch state."""

from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import VsaClient, VsaError
from ._common import READ_ONLY, AgentId, ClientFactory, ODataFilter, Skip, Top, fetch, result, rows_of, run_tool

SoftwareView = Literal["installed", "add_remove", "licenses", "security", "startup"]
_SOFTWARE = {
    "installed": "software/installedapplications",
    "add_remove": "software/addremoveprograms",
    "licenses": "software/licenses",
    "security": "software/securityproducts",
    "startup": "software/startupapps",
}
_HARDWARE = {"disk_volumes": "hardware/diskvolumes", "pci_and_disk": "hardware/pcianddisk", "printers": "hardware/printers"}


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def kaseya_vsa_list_agents(filter: ODataFilter = None, top: Top = 100, skip: Skip = None) -> str:
        """List agents (managed endpoints): name, machine group, OS, IP, online state, last check-in."""

        async def action(client: VsaClient) -> dict:
            return await fetch(client, "assetmgmt/agents", "agents", top, skip, filter)

        return await run_tool("kaseya_vsa_list_agents", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def kaseya_vsa_get_agent(agentId: AgentId) -> str:
        """Get one agent: name, machine group, OS, hardware summary, IPs, contact, online state."""

        async def action(client: VsaClient) -> Any:
            return result(await client.get(f"assetmgmt/agents/{agentId}"))

        return await run_tool("kaseya_vsa_get_agent", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def kaseya_vsa_get_software_inventory(
        agentId: AgentId,
        view: Annotated[SoftwareView, Field(description="installed applications (default), add/remove programs, licenses, security products or startup apps.")] = "installed",
        top: Top = 500,
    ) -> str:
        """Get an agent's software from its latest audit: installed apps, licenses, security products."""

        async def action(client: VsaClient) -> dict:
            return {"agent_id": agentId, "view": view} | await fetch(client, f"assetmgmt/audit/{agentId}/{_SOFTWARE[view]}", "software", top)

        return await run_tool("kaseya_vsa_get_software_inventory", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def kaseya_vsa_get_hardware_inventory(agentId: AgentId) -> str:
        """Get an agent's hardware from its latest audit: summary, disk volumes, PCI / disk devices, printers."""

        async def action(client: VsaClient) -> dict:
            out: dict[str, Any] = {"agent_id": agentId, "summary": result(await client.get(f"assetmgmt/audit/{agentId}/summary"))}
            for key, path in _HARDWARE.items():
                try:
                    out[key] = rows_of(await client.get(f"assetmgmt/audit/{agentId}/{path}", {"$top": 100}))
                except VsaError as e:
                    if e.status_code != 404:
                        raise
                    out[key] = []
            return out

        return await run_tool("kaseya_vsa_get_hardware_inventory", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def kaseya_vsa_get_patch_status(agentId: AgentId) -> str:
        """Get an agent's patch state (installed / missing counts, last scan) and its missing patches."""

        async def action(client: VsaClient) -> dict:
            status = result(await client.get(f"assetmgmt/patch/{agentId}/status"))
            missing = await fetch(client, f"assetmgmt/patch/{agentId}/machineupdate/False", "missing_patches", 200)
            return {"agent_id": agentId, "status": status} | missing

        return await run_tool("kaseya_vsa_get_patch_status", client_factory, action)
