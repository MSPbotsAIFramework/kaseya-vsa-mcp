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
"""Sign-in, request shapes, paging and tool behaviour against a mocked VSA server."""

import base64
import hashlib
import json

import httpx
import pytest

from kaseya_vsa_mcp import api_client
from kaseya_vsa_mcp.api_client import VsaClient, VsaCredentials, VsaError, legacy_auth_header
from kaseya_vsa_mcp.server import _credentials_var, create_mcp_server

BASE = "https://vsa.example.com/api/v1.0"
CREDS = VsaCredentials(BASE, "api-user", "pat-123")


def ok(value, **extra):
    return {"Result": value, "ResponseCode": 0, "Status": "OK", "Error": "None"} | extra


@pytest.fixture(autouse=True)
def no_sleep_and_fresh_sessions(monkeypatch):
    async def instant(_seconds):
        return None

    monkeypatch.setattr(api_client.asyncio, "sleep", instant)
    api_client._session_cache.clear()
    yield
    api_client._session_cache.clear()


class Recorder:
    """Mock VSA server: the /auth endpoints plus routes by method + path below /api/v1.0/."""

    def __init__(self, routes=None, default=None, auth=None):
        self.requests: list[httpx.Request] = []
        self.auth_requests: list[httpx.Request] = []
        self.routes = routes or {}
        self.default = default if default is not None else ok([])
        self.auth = auth

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/api/v1.0/")
        if path in ("auth", "auth/sso"):
            self.auth_requests.append(request)
            if callable(self.auth):
                return self.auth(request)
            return httpx.Response(200, json=ok({"Token": f"session-{len(self.auth_requests)}", "SessionExpiration": "2999-01-01T00:00:00Z"}))
        self.requests.append(request)
        reply = self.routes.get(f"{request.method} {path}", self.routes.get(path, self.default))
        if callable(reply):
            return reply(request)
        return httpx.Response(200, json=reply)

    def calls(self, path: str, method: str | None = None) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path == f"/api/v1.0/{path}" and (method is None or r.method == method)]


def body(request: httpx.Request):
    return json.loads(request.content) if request.content else None


async def _call(monkeypatch, recorder: Recorder, tool: str, args: dict, creds: VsaCredentials = CREDS):
    http = httpx.AsyncClient(transport=httpx.MockTransport(recorder))
    monkeypatch.setattr(api_client, "_get_shared_http_client", lambda: http)
    ctx = _credentials_var.set(creds)
    try:
        content, _ = await create_mcp_server().call_tool(tool, args)
    finally:
        _credentials_var.reset(ctx)
    return json.loads(content[0].text)


def _client(recorder: Recorder, creds: VsaCredentials = CREDS) -> VsaClient:
    return VsaClient(creds, httpx.AsyncClient(transport=httpx.MockTransport(recorder)))


# ---- sign-in ----------------------------------------------------------------


async def test_basic_sign_in_then_bearer_and_cached():
    rec = Recorder()
    client = _client(rec)
    await client.get("assetmgmt/agents")
    await client.get("assetmgmt/agents")
    assert len(rec.auth_requests) == 1
    assert rec.auth_requests[0].headers["authorization"] == "Basic " + base64.b64encode(b"api-user:pat-123").decode()
    assert rec.requests[0].headers["authorization"] == "Bearer session-1"


async def test_falls_back_to_legacy_hashed_sign_in():
    def auth(request):
        if request.headers["authorization"].startswith("Basic user="):
            return httpx.Response(200, json=ok({"Token": "legacy-session"}))
        return httpx.Response(401, json={"ResponseCode": 401, "Error": "Unauthorized"})

    rec = Recorder(auth=auth)
    await _client(rec).get("assetmgmt/agents")
    assert len(rec.auth_requests) == 2 and rec.requests[0].headers["authorization"] == "Bearer legacy-session"


def test_legacy_header_matches_the_documented_hashing():
    header = legacy_auth_header("user", "pass", "nonce123")
    sha256 = hashlib.sha256((hashlib.sha256(b"passuser").hexdigest() + "nonce123").encode()).hexdigest()
    sha1 = hashlib.sha1((hashlib.sha1(b"passuser").hexdigest() + "nonce123").encode()).hexdigest()
    assert header == f"Basic user=user,pass2={sha256},pass1={sha1},rand2=nonce123"


async def test_rejected_login_is_unauthorized(monkeypatch):
    rec = Recorder(auth=lambda r: httpx.Response(401, json={"ResponseCode": 401, "Error": "Unauthorized"}))
    result = await _call(monkeypatch, rec, "kaseya_vsa_list_agents", {})
    assert result["error"]["code"] == "unauthorized" and rec.requests == []
    assert "pat-123" not in json.dumps(result)


async def test_kaseya_one_token_uses_sso():
    rec = Recorder()
    await _client(rec, VsaCredentials(BASE, k1_token="k1-abc")).get("assetmgmt/agents")
    assert rec.auth_requests[0].url.path == "/api/v1.0/auth/sso"
    assert rec.auth_requests[0].headers["authorization"] == "Bearer k1-abc"


async def test_expired_session_signs_in_again():
    replies = iter([httpx.Response(401), httpx.Response(200, json=ok([]))])
    rec = Recorder({"assetmgmt/agents": lambda r: next(replies)})
    await _client(rec).get("assetmgmt/agents")
    assert len(rec.auth_requests) == 2 and rec.requests[1].headers["authorization"] == "Bearer session-2"


async def test_error_envelope_on_200(monkeypatch):
    rec = Recorder({"assetmgmt/agents/9": {"Result": None, "ResponseCode": 4001, "Status": "Error", "Error": "Agent not found"}})
    result = await _call(monkeypatch, rec, "kaseya_vsa_get_agent", {"agentId": "9"})
    assert result["error"]["code"] == "invalid_argument" and "Agent not found" in result["error"]["message"]


# ---- agents / audit / patches ----------------------------------------------


async def test_list_agents_pages_with_odata(monkeypatch):
    pages = {0: [{"AgentId": str(i)} for i in range(100)], 100: [{"AgentId": "x"} for _ in range(50)]}

    def agents(request):
        skip = int(request.url.params.get("$skip", "0"))
        return httpx.Response(200, json=ok(pages.get(skip, []), TotalRecords=150))

    rec = Recorder({"assetmgmt/agents": agents})
    result = await _call(monkeypatch, rec, "kaseya_vsa_list_agents", {"filter": "startswith(AgentName,'PC')", "top": 200})
    first, second = rec.calls("assetmgmt/agents")
    assert first.url.params["$top"] == "100" and first.url.params["$filter"] == "startswith(AgentName,'PC')" and "$skip" not in first.url.params
    assert second.url.params["$skip"] == "100"
    assert result["count"] == 150 and result["total"] == 150 and result["has_more"] is False


async def test_software_inventory_views(monkeypatch):
    rec = Recorder({"assetmgmt/audit/7/software/installedapplications": ok([{"ProductName": "7-Zip"}]), "assetmgmt/audit/7/software/licenses": ok([{"Product": "Office"}])})
    installed = await _call(monkeypatch, rec, "kaseya_vsa_get_software_inventory", {"agentId": "7"})
    assert installed["software"] == [{"ProductName": "7-Zip"}]
    licenses = await _call(monkeypatch, rec, "kaseya_vsa_get_software_inventory", {"agentId": "7", "view": "licenses"})
    assert licenses["software"] == [{"Product": "Office"}] and licenses["view"] == "licenses"


async def test_hardware_inventory_combines_audits(monkeypatch):
    rec = Recorder(
        {
            "assetmgmt/audit/7/summary": ok({"ComputerName": "PC7", "CpuType": "x64"}),
            "assetmgmt/audit/7/hardware/diskvolumes": ok([{"Drive": "C"}]),
            "assetmgmt/audit/7/hardware/pcianddisk": ok([{"Device": "NIC"}]),
            "assetmgmt/audit/7/hardware/printers": lambda r: httpx.Response(404),
        }
    )
    result = await _call(monkeypatch, rec, "kaseya_vsa_get_hardware_inventory", {"agentId": "7"})
    assert result["summary"] == {"ComputerName": "PC7", "CpuType": "x64"}
    assert result["disk_volumes"] == [{"Drive": "C"}] and result["pci_and_disk"] == [{"Device": "NIC"}] and result["printers"] == []


async def test_patch_status_and_missing(monkeypatch):
    rec = Recorder({"assetmgmt/patch/7/status": ok({"MissingPatches": 3}), "assetmgmt/patch/7/machineupdate/False": ok([{"KBArticle": "KB1"}])})
    result = await _call(monkeypatch, rec, "kaseya_vsa_get_patch_status", {"agentId": "7"})
    assert result["status"] == {"MissingPatches": 3} and result["missing_patches"] == [{"KBArticle": "KB1"}]


async def test_deploy_patches_needs_confirm(monkeypatch):
    rec = Recorder()
    preview = await _call(monkeypatch, rec, "kaseya_vsa_deploy_patches_now", {"agentId": "7"})
    assert preview["done"] is False and rec.requests == []
    await _call(monkeypatch, rec, "kaseya_vsa_deploy_patches_now", {"agentId": "7", "confirm": True})
    call = rec.calls("assetmgmt/patch/runnow", "PUT")[0]
    assert body(call) == {"AgentGuids": ["7"], "SkipIfOffline": False}


# ---- procedures / alarms / tickets / system ----------------------------------


async def test_list_and_run_procedures(monkeypatch):
    rec = Recorder({"automation/agentprocs": ok([{"AgentProcedureId": 11, "AgentProcedureName": "Clean temp"}]), "automation/agentprocs/7/scheduledprocs": lambda r: httpx.Response(404)})
    listed = await _call(monkeypatch, rec, "kaseya_vsa_list_procedures", {"agentId": "7"})
    assert listed["procedures"][0]["AgentProcedureId"] == 11 and listed["scheduled_on_agent"] == []
    preview = await _call(monkeypatch, rec, "kaseya_vsa_run_procedure", {"agentId": "7", "procedureId": "11"})
    assert preview["done"] is False and not rec.calls("automation/agentprocs/7/11/runnow")
    await _call(monkeypatch, rec, "kaseya_vsa_run_procedure", {"agentId": "7", "procedureId": "11", "confirm": True})
    assert rec.calls("automation/agentprocs/7/11/runnow", "PUT")


async def test_alarms_open_by_default(monkeypatch):
    rec = Recorder()
    await _call(monkeypatch, rec, "kaseya_vsa_list_alarms", {"filter": "AgentName eq 'PC7'"})
    await _call(monkeypatch, rec, "kaseya_vsa_list_alarms", {"include_closed": True})
    assert rec.requests[0].url.path.endswith("/assetmgmt/alarms/false") and rec.requests[0].url.params["$filter"] == "AgentName eq 'PC7'"
    assert rec.requests[1].url.path.endswith("/assetmgmt/alarms/true")


async def test_tickets_and_missing_module(monkeypatch):
    rec = Recorder({"automation/tickets": lambda r: httpx.Response(404), "automation/servicedesks/55/tickets": ok([{"Id": 1}])})
    missing = await _call(monkeypatch, rec, "kaseya_vsa_list_tickets", {})
    assert missing["tickets"] == [] and "Ticketing module" in missing["message"]
    desk = await _call(monkeypatch, rec, "kaseya_vsa_list_tickets", {"service_desk_id": "55"})
    assert desk["tickets"] == [{"Id": 1}]


async def test_orgs_and_machine_groups(monkeypatch):
    rec = Recorder({"system/orgs": ok([{"OrgId": 1}]), "system/machinegroups": ok([{"MachineGroupId": 2}])})
    orgs = await _call(monkeypatch, rec, "kaseya_vsa_list_organizations", {})
    groups = await _call(monkeypatch, rec, "kaseya_vsa_list_machine_groups", {"top": 10})
    assert orgs["organizations"] == [{"OrgId": 1}] and groups["machine_groups"] == [{"MachineGroupId": 2}]
    assert rec.calls("system/machinegroups")[0].url.params["$top"] == "10"


async def test_get_retries_5xx_but_puts_do_not():
    replies = iter([httpx.Response(502), httpx.Response(200, json=ok([]))])
    rec = Recorder({"GET assetmgmt/agents": lambda r: next(replies), "PUT assetmgmt/patch/runnow": lambda r: httpx.Response(500)})
    client = _client(rec)
    await client.get("assetmgmt/agents")
    with pytest.raises(VsaError):
        await client.put("assetmgmt/patch/runnow", {})
    assert len(rec.calls("assetmgmt/agents")) == 2 and len(rec.calls("assetmgmt/patch/runnow")) == 1



# ---- PRD-21070: tools that return next_skip take skip ------------------------------------------------
# Checklist: no skip sends the same request as before; skip goes to $skip; a cut page continues at
# skip + returned; walking next_skip returns every row once; skip past the end is empty; every tool
# whose result can carry next_skip declares skip (FastMCP drops undeclared arguments silently).

AGENT = "100633166984279"


def _odata(rows):
    """VSA OData collection: honours $top / $skip and reports TotalRecords."""

    def reply(request):
        top = int(request.url.params.get("$top", 100))
        skip = int(request.url.params.get("$skip", 0))
        return httpx.Response(200, json=ok(rows[skip : skip + top], TotalRecords=len(rows)))

    return reply


def _wide(prefix, n):
    return [{"Id": f"{prefix}{i:05d}", "Name": f"{prefix} {i}", **{f"F{k}": f"value {k}" for k in range(40)}} for i in range(n)]


SKIP_TOOLS = [
    ("kaseya_vsa_get_software_inventory", f"assetmgmt/audit/{AGENT}/software/installedapplications", "software",
     {"agentId": AGENT, "view": "installed", "top": 200}),
    ("kaseya_vsa_list_procedures", "automation/agentprocs", "procedures", {"agentId": AGENT}),
    ("kaseya_vsa_get_patch_status", f"assetmgmt/patch/{AGENT}/machineupdate/False", "missing_patches", {"agentId": AGENT}),
]


def _routes(path, rows):
    return {path: _odata(rows), f"assetmgmt/patch/{AGENT}/status": ok({"Missing": len(rows)}),
            f"automation/agentprocs/{AGENT}/scheduledprocs": ok([{"Id": "sched-1"}])}


@pytest.mark.parametrize("tool,path,key,args", SKIP_TOOLS)
async def test_cut_pages_walked_by_next_skip_return_every_row_once(monkeypatch, tool, path, key, args):
    rows = _wide("r", 1234)
    rec = Recorder(_routes(path, rows))
    ids, cut, calls, call_args = [], 0, 0, dict(args)
    while True:
        out = await _call(monkeypatch, rec, tool, call_args)
        calls += 1
        assert "retry_page_size" not in out
        cut += bool(out.get("truncated"))
        ids += [r["Id"] for r in out[key]]
        if out.get("next_skip") is None:
            break
        call_args = args | {"skip": out["next_skip"]}
        assert calls < 300
    assert cut > 0  # pages really were cut
    assert ids == [r["Id"] for r in rows]  # no gaps, no duplicates, nothing looped on page 1


@pytest.mark.parametrize("tool,path,key,args", SKIP_TOOLS)
async def test_skip_changes_the_page(monkeypatch, tool, path, key, args):
    rows = [{"Id": f"r{i:05d}"} for i in range(1000)]
    rec = Recorder(_routes(path, rows))
    first = await _call(monkeypatch, rec, tool, args)
    later = await _call(monkeypatch, rec, tool, args | {"skip": 300})
    assert first[key][0]["Id"] == "r00000" and later[key][0]["Id"] == "r00300"
    assert "$skip" not in rec.calls(path)[0].url.params  # no skip: the same request as before
    assert any(r.url.params.get("$skip") == "300" for r in rec.calls(path))


@pytest.mark.parametrize("tool,path,key,args", SKIP_TOOLS)
async def test_skip_past_the_end_is_empty(monkeypatch, tool, path, key, args):
    rec = Recorder(_routes(path, [{"Id": f"r{i}"} for i in range(40)]))
    out = await _call(monkeypatch, rec, tool, args | {"skip": 500})
    assert (out[key], out["has_more"], out.get("next_skip")) == ([], False, None)


async def test_procedures_default_request_is_unchanged_and_keeps_scheduled(monkeypatch):
    rec = Recorder(_routes("automation/agentprocs", [{"Id": f"p{i}"} for i in range(30)]))
    out = await _call(monkeypatch, rec, "kaseya_vsa_list_procedures", {"agentId": AGENT})
    assert [r.url.params["$top"] for r in rec.calls("automation/agentprocs")] == ["100"]
    assert out["count"] == 30 and out["scheduled_on_agent"] == [{"Id": "sched-1"}]


async def test_every_tool_that_can_return_next_skip_declares_skip():
    # fetch() always reports next_skip; a tool without a skip parameter would make callers loop on page 1.
    import inspect
    import re

    from kaseya_vsa_mcp.tools import agents, automation, monitoring, system

    tools = {t.name: t for t in await create_mcp_server().list_tools()}
    for module in (agents, automation, monitoring, system):
        source = inspect.getsource(module)
        for name, body in re.findall(r"async def (kaseya_vsa_\w+)\((.*?)return await run_tool", source, re.S):
            if "fetch(client" in body:
                assert "skip" in tools[name].inputSchema["properties"], name


# ---- PRD-21071: licence keys masked by default ---------------------------------------------------------


LICENSES = [
    {"ProductName": "Internet Explorer", "ProductKey": "GMJ3N-ABCDE-FGHIJ-KLMNO-PQRST", "LicenseCode": "LC-1234567890ABC"},
    {"ProductName": "Short", "ProductKey": "AB12", "LicenseCode": None, "licenseKey": ""},
]


async def test_licence_keys_are_masked_unless_asked_for(monkeypatch):
    rec = Recorder({f"assetmgmt/audit/{AGENT}/software/licenses": _odata(LICENSES)})
    out = await _call(monkeypatch, rec, "kaseya_vsa_get_software_inventory", {"agentId": AGENT, "view": "licenses"})
    first, short = out["software"]
    assert out["keys_masked"] is True
    assert first["ProductKey"] == "*****PQRST" and first["LicenseCode"] == "*****90ABC"
    assert short["ProductKey"] == "*****"  # too short to show any of it
    assert "LicenseCode" not in short or short["LicenseCode"] is None
    assert first["ProductName"] == "Internet Explorer"
    full = await _call(monkeypatch, rec, "kaseya_vsa_get_software_inventory", {"agentId": AGENT, "view": "licenses", "showKeys": True})
    assert full["software"][0]["ProductKey"] == "GMJ3N-ABCDE-FGHIJ-KLMNO-PQRST" and "keys_masked" not in full


async def test_other_software_views_are_not_masked(monkeypatch):
    rows = [{"ProductName": "App", "ProductKey": "GMJ3N-ABCDE-FGHIJ-KLMNO-PQRST"}]
    rec = Recorder({f"assetmgmt/audit/{AGENT}/software/installedapplications": _odata(rows)})
    out = await _call(monkeypatch, rec, "kaseya_vsa_get_software_inventory", {"agentId": AGENT})
    assert out["software"][0]["ProductKey"] == "GMJ3N-ABCDE-FGHIJ-KLMNO-PQRST" and "keys_masked" not in out


async def test_filter_description_shows_the_decimal_id_suffix():
    tools = {t.name: t for t in await create_mcp_server().list_tools()}
    description = tools["kaseya_vsa_list_agents"].inputSchema["properties"]["filter"]
    text = json.dumps(description)
    assert "OrgId eq 10158420681076233316854711M" in text
