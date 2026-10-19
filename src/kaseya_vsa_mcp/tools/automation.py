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
"""Actions on an endpoint: deploy patches now, list and run agent procedures."""

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import VsaClient, VsaError
from ._common import DESTRUCTIVE, READ_ONLY, AgentId, ClientFactory, Confirm, fetch, not_confirmed, rows_of, run_tool

ProcedureId = Annotated[str, Field(description="Agent procedure id (from kaseya_vsa_list_procedures).", min_length=1)]


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=DESTRUCTIVE)
    async def kaseya_vsa_deploy_patches_now(agentId: AgentId, confirm: Confirm = None) -> str:
        """Install the agent's approved missing patches now (may reboot it). Needs confirm: true.

        Only when the user explicitly asks; check kaseya_vsa_get_patch_status first.
        """

        async def action(client: VsaClient) -> Any:
            if confirm is not True:
                return not_confirmed(f"Install the approved missing patches on agent {agentId} now (the machine may reboot)")
            await client.put("assetmgmt/patch/runnow", {"AgentGuids": [agentId], "SkipIfOffline": False})
            return {"done": True, "agent_id": agentId, "message": "Patch update scheduled to run now."}

        return await run_tool("kaseya_vsa_deploy_patches_now", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def kaseya_vsa_list_procedures(agentId: AgentId) -> str:
        """List agent procedures that can be run, plus the ones already scheduled on this agent."""

        async def action(client: VsaClient) -> dict:
            available = await fetch(client, "automation/agentprocs", "procedures", 500)
            try:
                scheduled = rows_of(await client.get(f"automation/agentprocs/{agentId}/scheduledprocs", {"$top": 100}))
            except VsaError as e:
                if e.status_code != 404:
                    raise
                scheduled = []
            return {"agent_id": agentId} | available | {"scheduled_on_agent": scheduled}

        return await run_tool("kaseya_vsa_list_procedures", client_factory, action)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def kaseya_vsa_run_procedure(agentId: AgentId, procedureId: ProcedureId, confirm: Confirm = None) -> str:
        """Run an agent procedure on an agent now. Needs confirm: true.

        Executes the procedure's steps on the endpoint. Only when the user explicitly asks.
        """

        async def action(client: VsaClient) -> Any:
            if confirm is not True:
                return not_confirmed(f"Run agent procedure {procedureId} on agent {agentId} now")
            await client.put(f"automation/agentprocs/{agentId}/{procedureId}/runnow")
            return {"done": True, "agent_id": agentId, "procedure_id": procedureId, "message": "Procedure queued to run now."}

        return await run_tool("kaseya_vsa_run_procedure", client_factory, action)
