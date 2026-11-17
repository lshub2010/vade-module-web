"""Adapter tests: manifest identity, schema generation, error mapping, CLI.

Skipped entirely when the SDK is not installed, so `pytest tests -q` still runs
on a bare Python (that is the module's own gate). The SDK is looked up in the
usual three places: `VADE_SDK_PATH`, a vendored `sdk/python`, and the sibling
Vade checkout used during development.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

MODULE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MODULE_ROOT / "src"))


def _sdk_candidates() -> list[Path]:
    candidates: list[Path] = []
    if os.environ.get("VADE_SDK_PATH"):
        candidates.append(Path(os.environ["VADE_SDK_PATH"]))
    # vendored (repo layout `modules/web`), then the local dev checkout
    candidates.append(MODULE_ROOT / "sdk" / "python")
    candidates.append(MODULE_ROOT.parent / "Vade" / "sdk" / "python")
    candidates.append(MODULE_ROOT.parents[1] / "sdk" / "python")
    return candidates


SDK_DIR = next((path for path in _sdk_candidates() if (path / "vade_sdk").is_dir()), None)
if SDK_DIR is not None:
    sys.path.insert(0, str(SDK_DIR))

pytest.importorskip("vade_sdk", reason="vade-sdk is required for the adapter tests")

from web_module import server, tools  # noqa: E402


@pytest.fixture()
def app():
    return server.build_app()


def test_module_identity_is_stable():
    assert server.MODULE_ID == "com.example.web"
    assert server.MODULE_VERSION == "1.0.0"


def test_committed_manifest_matches_print_manifest(app):
    committed = json.loads((MODULE_ROOT / "manifest.json").read_text(encoding="utf-8"))
    assert app.manifest() == committed


def test_check_is_clean(app):
    assert app.check() == []


def test_schema_comes_from_the_tool_signature(app):
    fetch = app.tool("web_fetch").input_schema
    assert fetch["required"] == ["url"]
    assert fetch["properties"]["url"] == {"type": "string"}
    assert fetch["properties"]["max_bytes"] == {"type": "integer", "default": tools.DEFAULT_MAX_BYTES}
    assert fetch["additionalProperties"] is False

    head = app.tool("web_head").input_schema
    assert head["required"] == ["url"]
    assert list(head["properties"]) == ["url"]


def test_tool_metadata_comes_from_the_decorator(app):
    for fn in tools.all_tools():
        meta = fn.tool_meta  # type: ignore[attr-defined]
        spec = app.tool(meta["name"])
        assert spec.description == meta["description"]
        assert spec.risk == meta["risk"]
        assert spec.timeout_ms == meta["timeout_ms"]
        assert spec.idempotent is meta["idempotent"]


def test_risk_levels_are_declared_per_tool(app):
    assert app.tool("web_fetch").risk == "medium"
    assert app.tool("web_fetch").idempotent is True
    assert app.tool("web_head").risk == "low"
    assert app.tool("web_head").idempotent is True
    assert [name for name in app.tool_names if app.tool(name).risk == "medium"] == ["web_fetch"]


def test_module_is_pooled_and_declares_tools_only(app):
    manifest = app.manifest()
    assert manifest["concurrency"] == "pooled"
    assert manifest["capabilities"].keys() == {"tools"}
    assert [tool["name"] for tool in manifest["capabilities"]["tools"]] == ["web_fetch", "web_head"]


async def test_ssrf_denial_keeps_its_code_through_the_adapter(app):
    envelope = await app.call_tool("web_fetch", {"url": "http://169.254.169.254/latest/meta-data/"})
    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "PERMISSION_DENIED"
    assert envelope["error"]["retriable"] is False
    assert "169.254.169.254" not in envelope["error"]["message"]


async def test_file_scheme_is_denied_through_the_adapter(app):
    for url in ("file:///etc/passwd", "ftp://example.com/x", "data:text/plain,hi"):
        envelope = await app.call_tool("web_fetch", {"url": url})
        assert envelope["error"]["code"] == "PERMISSION_DENIED", url


async def test_bad_max_bytes_is_an_argument_error(app):
    envelope = await app.call_tool("web_fetch", {"url": "http://example.com/", "max_bytes": 0})
    assert envelope["error"]["code"] == "INVALID_ARGUMENT"
    envelope = await app.call_tool("web_fetch", {"url": "http://example.com/", "max_bytes": 2 * 1024 * 1024})
    assert envelope["error"]["code"] == "INVALID_ARGUMENT"


async def test_unknown_tool_is_not_found(app):
    assert (await app.call_tool("shell_exec", {"cmd": "id"}))["error"]["code"] == "NOT_FOUND"


async def test_wrong_type_is_rejected_by_the_sdk(app):
    envelope = await app.call_tool("web_fetch", {"url": 123})
    assert envelope["error"]["code"] == "INVALID_ARGUMENT"


async def test_unknown_argument_is_rejected(app):
    envelope = await app.call_tool("web_head", {"url": "http://example.com/", "timeout": 1})
    assert envelope["error"]["code"] == "INVALID_ARGUMENT"


async def test_missing_argument_is_rejected(app):
    assert (await app.call_tool("web_fetch", {}))["error"]["code"] == "INVALID_ARGUMENT"


def _cli_env(**extra: str) -> dict[str, str]:
    env = dict(os.environ)
    parts = [str(MODULE_ROOT / "src")]
    if SDK_DIR is not None:
        parts.append(str(SDK_DIR))
    if env.get("PYTHONPATH"):
        parts.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(parts)
    env.update(extra)
    return env


def test_standalone_entrypoint_denies_an_internal_target():
    """The real CLI, in a fresh interpreter: no network is touched."""
    completed = subprocess.run(
        [sys.executable, "-m", "web_module", "--standalone", "web_fetch", "--args", '{"url":"http://127.0.0.1:8443/"}'],
        cwd=MODULE_ROOT,
        env=_cli_env(),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode != 0
    assert "PERMISSION_DENIED" in completed.stderr
    assert "127.0.0.1" not in completed.stderr


def test_print_manifest_is_byte_identical_to_the_committed_file():
    completed = subprocess.run(
        [sys.executable, "-m", "web_module", "--print-manifest"],
        cwd=MODULE_ROOT,
        env=_cli_env(),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == (MODULE_ROOT / "manifest.json").read_text(encoding="utf-8")
