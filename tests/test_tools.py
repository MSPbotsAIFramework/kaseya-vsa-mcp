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
"""tools/list snapshot, annotations and error-envelope mapping. No network access."""

import asyncio
import json

import pytest

from kaseya_vsa_mcp.api_client import VsaError
from kaseya_vsa_mcp.server import INSTRUCTIONS, create_mcp_server

A = {"agentId"}

# Tool names are a public contract: existing agents and tenant connections
# depend on them. Changing this snapshot is a breaking change.
EXPECTED_TOOLS: dict[str, set[str]] = {
    "kaseya_vsa_list_agents": set(),
    "kaseya_vsa_get_agent": A,
    "kaseya_vsa_get_software_inventory": A,
    "kaseya_vsa_get_hardware_inventory": A,
    "kaseya_vsa_get_patch_status": A,
    "kaseya_vsa_deploy_patches_now": A,
    "kaseya_vsa_list_procedures": A,
    "kaseya_vsa_run_procedure": A | {"procedureId"},
    "kaseya_vsa_list_alarms": set(),
    "kaseya_vsa_list_tickets": set(),
    "kaseya_vsa_list_organizations": set(),
    "kaseya_vsa_list_machine_groups": set(),
}
# Every parameter the earlier version declared is still accepted.
UPSTREAM_PARAMS = {
    "kaseya_vsa_list_agents": {"filter", "top", "skip"},
    "kaseya_vsa_list_alarms": {"filter", "top"},
    "kaseya_vsa_list_tickets": {"filter", "top"},
    "kaseya_vsa_list_organizations": {"top"},
    "kaseya_vsa_list_machine_groups": {"top"},
}
CONFIRM_TOOLS = {"kaseya_vsa_deploy_patches_now", "kaseya_vsa_run_procedure"}


@pytest.fixture(scope="module")
def tools():
    return {t.name: t for t in asyncio.run(create_mcp_server().list_tools())}


def test_tool_names_are_stable(tools):
    assert set(tools) == set(EXPECTED_TOOLS)


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_required_params(tools, name):
    assert set(tools[name].inputSchema.get("required", [])) == EXPECTED_TOOLS[name]


@pytest.mark.parametrize("name", sorted(UPSTREAM_PARAMS))
def test_earlier_params_still_accepted(tools, name):
    assert UPSTREAM_PARAMS[name] <= set(tools[name].inputSchema["properties"])


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_description_budget(tools, name):
    description = (tools[name].description or "").strip()
    assert description, f"{name} has no description"
    assert len(description) <= 500
    assert len(description.splitlines()[0]) <= 100


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_annotations_match_side_effects(tools, name):
    annotations = tools[name].annotations
    assert annotations is not None
    assert annotations.readOnlyHint is (name not in CONFIRM_TOOLS)
    assert bool(annotations.destructiveHint) is (name in CONFIRM_TOOLS)


@pytest.mark.parametrize("name", sorted(CONFIRM_TOOLS))
def test_endpoint_actions_need_confirm(tools, name):
    assert "confirm" in tools[name].inputSchema["properties"]
    assert "explicitly ask" in tools[name].description


def test_instructions_budget():
    assert len(INSTRUCTIONS) <= 1500
    assert "\n" in INSTRUCTIONS


@pytest.mark.parametrize(
    "status,code,retryable",
    [
        (401, "unauthorized", False),
        (403, "unauthorized", False),
        (404, "not_found", False),
        (400, "invalid_argument", False),
        (429, "rate_limited", True),
        (500, "upstream_error", True),
        (0, "upstream_error", True),
    ],
)
def test_error_envelope(status, code, retryable):
    envelope = json.loads(VsaError(status, "boom").to_envelope())
    assert envelope == {"error": {"code": code, "message": "boom", "retryable": retryable}}


def test_tool_without_credentials_returns_not_configured():
    content, _ = asyncio.run(create_mcp_server().call_tool("kaseya_vsa_list_agents", {}))
    assert json.loads(content[0].text)["error"]["code"] == "not_configured"
