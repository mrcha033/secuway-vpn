#!/usr/bin/env python3
"""Validate the independent, self-contained dual-marketplace package."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAME = "secuway-vpn"
VERSION = "0.4.0"
REPOSITORY = "https://github.com/mrcha033/secuway-vpn"
PLUGIN = ROOT / "plugins" / NAME
SKILL = PLUGIN / "skills" / NAME
EXPECTED_ASSETS = {
    f"windows-{architecture}/{filename}"
    for architecture in ("amd64", "arm64")
    for filename in ("lea.dll", "provider_smoke.exe", "secuway.exe")
}
SECRET_PATH_SUFFIXES = {
    ".cer",
    ".crt",
    ".env",
    ".key",
    ".mobileconfig",
    ".ovpn",
    ".p12",
    ".pem",
    ".pfx",
}
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----"),
    re.compile(rb"-----BEGIN CERTIFICATE-----"),
    re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{16,}\b"),
)


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), f"{path} must contain a JSON object"
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def files_below(root: Path) -> list[Path]:
    result: list[Path] = []
    for path in root.rglob("*"):
        assert not path.is_symlink(), f"self-contained payload cannot use {path}"
        assert path.name != ".DS_Store"
        assert "__pycache__" not in path.parts
        assert path.suffix not in {".pyc", ".pyo"}
        if path.is_file():
            result.append(path.relative_to(root))
    return sorted(result)


def pe_information(path: Path) -> tuple[int, bool]:
    data = path.read_bytes()
    assert data[:2] == b"MZ", f"{path} is not PE"
    offset = int.from_bytes(data[0x3C:0x40], "little")
    assert data[offset : offset + 4] == b"PE\0\0"
    machine = int.from_bytes(data[offset + 4 : offset + 6], "little")
    characteristics = int.from_bytes(data[offset + 22 : offset + 24], "little")
    return machine, bool(characteristics & 0x2000)


def assert_no_secret_material(root: Path) -> None:
    for relative in files_below(root):
        path = root / relative
        assert (
            path.suffix.casefold() not in SECRET_PATH_SUFFIXES
        ), f"credential-bearing file path: {relative}"
        data = path.read_bytes()
        for pattern in SECRET_PATTERNS:
            assert not pattern.search(data), f"secret material in {relative}"


def main() -> None:
    catalog = load_json(ROOT / "release/catalog.json")
    assert catalog["schema"] == "secuway-vpn-release-catalog/v1"
    assert catalog["product"] == {
        "name": NAME,
        "version": VERSION,
        "license": "MIT",
        "homepage": REPOSITORY,
        "repository": REPOSITORY,
    }
    assert catalog["plugin"] == {
        "name": NAME,
        "version": VERSION,
        "marketplace": NAME,
        "canonicalSkillPath": "plugins/secuway-vpn/skills/secuway-vpn",
    }
    assert catalog["releaseTag"] == f"v{VERSION}"
    spdx_created = datetime.fromisoformat(
        catalog["spdxCreated"].replace("Z", "+00:00")
    )
    assert spdx_created.tzinfo is not None
    assert spdx_created <= datetime.now(timezone.utc)
    assert catalog["provenance"]["repository"] == (
        "https://github.com/mrcha033/skills"
    )
    assert catalog["provenance"]["commit"] == (
        "4e9b843bfcf434be9d76829355f0eee34939bc41"
    )
    assert catalog["provenance"]["path"] == "skills/secuway-vpn"

    assert not (ROOT / "skills" / NAME).exists(), (
        "the nested plugin skill must be the only canonical distribution tree"
    )
    assert SKILL.is_dir() and not SKILL.is_symlink()
    assert {
        path.name for path in (PLUGIN / "skills").iterdir() if path.is_dir()
    } == {NAME}
    assert not any(
        path.is_file() and path.name.casefold().startswith("readme")
        for path in SKILL.rglob("*")
    ), "the skill folder must not gain an extraneous README"
    assert (SKILL / "SKILL.md").read_text(encoding="utf-8").startswith(
        "---\nname: secuway-vpn\n"
    )

    codex_market = load_json(ROOT / ".agents/plugins/marketplace.json")
    claude_market = load_json(ROOT / ".claude-plugin/marketplace.json")
    assert codex_market["name"] == claude_market["name"] == NAME
    assert len(codex_market["plugins"]) == len(claude_market["plugins"]) == 1
    codex_entry = codex_market["plugins"][0]
    claude_entry = claude_market["plugins"][0]
    assert codex_entry == {
        "name": NAME,
        "source": {"source": "local", "path": "./plugins/secuway-vpn"},
        "policy": {
            "installation": "AVAILABLE",
            "authentication": "ON_INSTALL",
        },
        "category": "Developer Tools",
    }
    assert claude_entry["name"] == NAME
    assert claude_entry["source"] == "./plugins/secuway-vpn"
    assert claude_entry["version"] == VERSION
    assert claude_entry["homepage"] == claude_entry["repository"] == REPOSITORY

    codex_plugin = load_json(PLUGIN / ".codex-plugin/plugin.json")
    claude_plugin = load_json(PLUGIN / ".claude-plugin/plugin.json")
    for manifest in (codex_plugin, claude_plugin):
        assert manifest["name"] == NAME
        assert manifest["version"] == VERSION
        assert manifest["skills"] == "./skills/"
        assert manifest["homepage"] == manifest["repository"] == REPOSITORY
        assert manifest["license"] == "MIT"
    assert codex_plugin["interface"]["websiteURL"] == REPOSITORY
    assert not {"hooks", "apps", "mcpServers"} & set(codex_plugin)

    asset_manifest = load_json(SKILL / "assets/manifest.json")
    assert asset_manifest["schema"] == "secuway-windows-assets/v1"
    assert asset_manifest["version"] == VERSION
    assert asset_manifest["source"]["repository"] == REPOSITORY
    assert set(asset_manifest["assets"]) == EXPECTED_ASSETS
    actual_assets = {
        path.relative_to(SKILL / "assets").as_posix()
        for path in (SKILL / "assets").rglob("*")
        if path.is_file() and path.name != "manifest.json"
    }
    assert actual_assets == EXPECTED_ASSETS
    machines = {"amd64": 0x8664, "arm64": 0xAA64}
    for relative, record in asset_manifest["assets"].items():
        path = SKILL / "assets" / relative
        assert record == {"bytes": path.stat().st_size, "sha256": sha256(path)}
        architecture = relative.split("/", 1)[0].removeprefix("windows-")
        machine, is_dll = pe_information(path)
        assert machine == machines[architecture]
        assert is_dll == relative.endswith(".dll")

    licenses = load_json(SKILL / "licenses/manifest.json")
    assert licenses["schema"] == "secuway-third-party-licenses/v1"
    component_names = {item["name"] for item in licenses["components"]}
    assert {
        "Go toolchain and standard library",
        "golang.org/x/sys",
        "golang.org/x/term",
        "Crypto++",
        "GCC runtime libraries",
        "LLVM runtime libraries",
        "MinGW-w64 runtime (AMD64 build)",
        "MinGW-w64 runtime (ARM64 build)",
    } <= component_names
    for component in licenses["components"]:
        assert set(component["included_in"]) <= EXPECTED_ASSETS
        for record in component["files"]:
            path = SKILL / "licenses" / record["path"]
            assert path.is_file()
            assert sha256(path) == record["sha256"]
    assert {item["name"] for item in licenses["not_redistributed"]} == {
        "OpenVPN Community",
        "OpenSSL libcrypto",
    }
    assert (SKILL / "licenses/THIRD_PARTY_NOTICES.md").is_file()
    assert (ROOT / "LICENSE").read_text(encoding="utf-8").startswith(
        "MIT License\n"
    )
    assert (PLUGIN / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
    assert_no_secret_material(PLUGIN)

    print(
        "independent dual-marketplace packaging: PASS "
        f"({len(files_below(SKILL))} canonical skill files)"
    )


if __name__ == "__main__":
    main()
