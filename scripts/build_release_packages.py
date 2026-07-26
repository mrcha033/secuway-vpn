#!/usr/bin/env python3
"""Build and validate deterministic Secuway VPN release packages."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "release" / "catalog.json"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
ARCHITECTURES = ("amd64", "arm64")
EXPECTED_ARTIFACT_KEYS = {
    "standaloneZip",
    "standaloneSkill",
    "pluginZip",
    "windowsAmd64Zip",
    "windowsArm64Zip",
    "spdxSbom",
}
EXPECTED_PE_FILES = {"lea.dll", "provider_smoke.exe", "secuway.exe"}
WINDOWS_SCRIPTS = ("Setup-Windows.ps1", "Install-WindowsRuntime.ps1")
SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_SECRET_SUFFIXES = {
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
FORBIDDEN_SECRET_NAMES = {
    "auth.txt",
    "credentials.json",
    "secrets.json",
}
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----"),
    re.compile(rb"-----BEGIN CERTIFICATE-----"),
    re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{16,}\b"),
)
VALID_DECLARED_LICENSES = {
    "Apache-2.0 WITH LLVM-exception",
    "BSD-3-Clause",
    "GPL-3.0-or-later WITH GCC-exception-3.1",
    "MIT",
}


class PackagingError(RuntimeError):
    """Raised when source or output violates the release contract."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PackagingError(f"cannot read JSON object {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PackagingError(f"{path} must contain a JSON object")
    return value


def json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_mode(path: Path) -> int:
    return 0o755 if path.stat().st_mode & 0o111 else 0o644


def relative_files(root: Path) -> list[Path]:
    if not root.is_dir() or root.is_symlink():
        raise PackagingError(f"package root must be a real directory: {root}")
    files: list[Path] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if path.is_symlink():
            raise PackagingError(f"symlinks are forbidden in packages: {path}")
        if (
            path.name == ".DS_Store"
            or "__pycache__" in relative.parts
            or path.suffix in {".pyc", ".pyo"}
        ):
            raise PackagingError(f"generated junk is forbidden in packages: {path}")
        if path.is_file():
            files.append(relative)
    return sorted(files, key=lambda item: item.as_posix())


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for relative in relative_files(root):
        path = root / relative
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(f"{normalized_mode(path):03o}".encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def assert_safe_member(name: str) -> None:
    pure = PurePosixPath(name)
    if (
        not name
        or pure.is_absolute()
        or ".." in pure.parts
        or "\\" in name
        or pure.as_posix() != name
    ):
        raise PackagingError(f"unsafe archive member: {name!r}")


def assert_secret_free(name: str, data: bytes) -> None:
    assert_safe_member(name)
    path = PurePosixPath(name)
    lowered_name = path.name.casefold()
    lowered_suffix = path.suffix.casefold()
    if (
        lowered_name in FORBIDDEN_SECRET_NAMES
        or lowered_suffix in FORBIDDEN_SECRET_SUFFIXES
    ):
        raise PackagingError(f"credential-bearing path is forbidden: {name}")
    for pattern in SECRET_PATTERNS:
        if pattern.search(data):
            raise PackagingError(f"recognized secret material in {name}")


def tree_entries(root: Path, prefix: str = "") -> dict[str, tuple[bytes, int]]:
    result: dict[str, tuple[bytes, int]] = {}
    for relative in relative_files(root):
        name = (
            PurePosixPath(prefix) / PurePosixPath(relative.as_posix())
        ).as_posix()
        path = root / relative
        data = path.read_bytes()
        assert_secret_free(name, data)
        result[name] = (data, normalized_mode(path))
    return result


def zip_info(name: str, mode: int) -> zipfile.ZipInfo:
    assert_safe_member(name)
    if mode not in {0o644, 0o755}:
        raise PackagingError(f"unsupported normalized mode {mode:o}: {name}")
    info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = (stat.S_IFREG | mode) << 16
    return info


def write_archive(
    destination: Path, entries: dict[str, tuple[bytes, int]]
) -> None:
    if not entries:
        raise PackagingError(f"refusing to write empty archive: {destination}")
    with zipfile.ZipFile(
        destination, mode="w", compression=zipfile.ZIP_STORED
    ) as archive:
        for name in sorted(entries):
            data, mode = entries[name]
            assert_secret_free(name, data)
            archive.writestr(zip_info(name, mode), data)


def artifact_record(path: Path) -> dict[str, Any]:
    return {
        "file": path.name,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def load_catalog(path: Path = DEFAULT_CATALOG) -> dict[str, Any]:
    catalog = load_json(path)
    if catalog.get("schema") != "secuway-vpn-release-catalog/v1":
        raise PackagingError("unsupported release catalog schema")
    product = catalog.get("product")
    plugin = catalog.get("plugin")
    if not isinstance(product, dict) or not isinstance(plugin, dict):
        raise PackagingError("catalog product and plugin must be objects")
    name = product.get("name")
    version = product.get("version")
    if name != "secuway-vpn":
        raise PackagingError("product name must be secuway-vpn")
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        raise PackagingError("product version must be valid SemVer")
    if (
        plugin.get("name") != name
        or plugin.get("version") != version
        or plugin.get("marketplace") != name
    ):
        raise PackagingError("product, plugin, and marketplace identity drift")
    repository = "https://github.com/mrcha033/secuway-vpn"
    if (
        product.get("homepage") != repository
        or product.get("repository") != repository
        or product.get("license") != "MIT"
    ):
        raise PackagingError("product repository or license metadata drift")
    if catalog.get("releaseTag") != f"v{version}":
        raise PackagingError("releaseTag must exactly match product version")
    if not isinstance(catalog.get("spdxCreated"), str):
        raise PackagingError("spdxCreated must be a fixed timestamp")
    artifacts = catalog.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != EXPECTED_ARTIFACT_KEYS:
        raise PackagingError(
            f"catalog artifacts must be exactly {sorted(EXPECTED_ARTIFACT_KEYS)}"
        )
    filenames = list(artifacts.values())
    if (
        not all(
            isinstance(item, str)
            and item == Path(item).name
            and item not in {"", ".", ".."}
            for item in filenames
        )
        or len(filenames) != len(set(filenames))
    ):
        raise PackagingError("artifact filenames must be unique safe basenames")
    provenance = catalog.get("provenance")
    if (
        not isinstance(provenance, dict)
        or provenance.get("kind") != "imported-and-normalized"
        or provenance.get("repository") != "https://github.com/mrcha033/skills"
        or provenance.get("commit")
        != "4e9b843bfcf434be9d76829355f0eee34939bc41"
        or provenance.get("path") != "skills/secuway-vpn"
    ):
        raise PackagingError("release provenance metadata drift")
    return catalog


def pe_information(path: Path) -> tuple[int, bool]:
    data = path.read_bytes()
    if len(data) < 64 or data[:2] != b"MZ":
        raise PackagingError(f"not a PE file: {path}")
    offset = int.from_bytes(data[0x3C:0x40], "little")
    if offset + 24 > len(data) or data[offset : offset + 4] != b"PE\0\0":
        raise PackagingError(f"invalid PE header: {path}")
    machine = int.from_bytes(data[offset + 4 : offset + 6], "little")
    characteristics = int.from_bytes(data[offset + 22 : offset + 24], "little")
    return machine, bool(characteristics & 0x2000)


def validate_asset_manifest(
    skill_root: Path, version: str
) -> dict[str, Any]:
    assets_root = skill_root / "assets"
    manifest = load_json(assets_root / "manifest.json")
    if (
        manifest.get("schema") != "secuway-windows-assets/v1"
        or manifest.get("version") != version
    ):
        raise PackagingError("Windows asset manifest schema/version drift")
    source = manifest.get("source")
    if (
        not isinstance(source, dict)
        or source.get("repository")
        != "https://github.com/mrcha033/secuway-vpn"
        or not SHA256_HEX.fullmatch(str(source.get("provider_source_sha256", "")))
        or not SHA256_HEX.fullmatch(
            str(source.get("provider_smoke_source_sha256", ""))
        )
    ):
        raise PackagingError("Windows asset source metadata drift")
    expected_paths = {
        f"windows-{architecture}/{filename}"
        for architecture in ARCHITECTURES
        for filename in EXPECTED_PE_FILES
    }
    records = manifest.get("assets")
    if not isinstance(records, dict) or set(records) != expected_paths:
        raise PackagingError("Windows asset inventory drift")
    actual_paths = {
        path.relative_to(assets_root).as_posix()
        for path in assets_root.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    }
    if actual_paths != expected_paths:
        raise PackagingError("Windows asset files do not match their manifest")
    expected_machines = {"amd64": 0x8664, "arm64": 0xAA64}
    for relative in sorted(expected_paths):
        path = assets_root / relative
        record = records[relative]
        if not isinstance(record, dict):
            raise PackagingError(f"invalid asset record: {relative}")
        if (
            record.get("bytes") != path.stat().st_size
            or record.get("sha256") != sha256_file(path)
        ):
            raise PackagingError(f"asset hash/size drift: {relative}")
        architecture = relative.split("/", 1)[0].removeprefix("windows-")
        machine, is_dll = pe_information(path)
        if machine != expected_machines[architecture]:
            raise PackagingError(f"asset architecture drift: {relative}")
        if is_dll != relative.endswith(".dll"):
            raise PackagingError(f"asset PE kind drift: {relative}")
    openvpn = manifest.get("openvpn")
    if (
        not isinstance(openvpn, dict)
        or not isinstance(openvpn.get("version"), str)
    ):
        raise PackagingError("OpenVPN prerequisite metadata is missing")
    for architecture in ARCHITECTURES:
        record = openvpn.get(architecture)
        if (
            not isinstance(record, dict)
            or not str(record.get("url", "")).startswith("https://")
            or not SHA256_HEX.fullmatch(str(record.get("sha256", "")))
        ):
            raise PackagingError(
                f"OpenVPN {architecture} prerequisite metadata is invalid"
            )
    return manifest


def validate_license_manifest(
    skill_root: Path, asset_manifest: dict[str, Any]
) -> dict[str, Any]:
    licenses_root = skill_root / "licenses"
    manifest = load_json(licenses_root / "manifest.json")
    if manifest.get("schema") != "secuway-third-party-licenses/v1":
        raise PackagingError("third-party license manifest schema drift")
    components = manifest.get("components")
    external = manifest.get("not_redistributed")
    if not isinstance(components, list) or not isinstance(external, list):
        raise PackagingError("third-party component lists are missing")
    names: set[str] = set()
    for component in components:
        if not isinstance(component, dict):
            raise PackagingError("third-party component must be an object")
        name = component.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise PackagingError(f"invalid duplicate component name: {name!r}")
        names.add(name)
        included = component.get("included_in")
        files = component.get("files")
        if (
            not isinstance(included, list)
            or not included
            or not set(included) <= set(asset_manifest["assets"])
            or not isinstance(files, list)
            or not files
        ):
            raise PackagingError(f"invalid component coverage: {name}")
        for record in files:
            if not isinstance(record, dict):
                raise PackagingError(f"invalid license record: {name}")
            relative = record.get("path")
            if not isinstance(relative, str):
                raise PackagingError(f"invalid license path: {name}")
            path = licenses_root / PurePosixPath(relative)
            if (
                not path.is_file()
                or path.is_symlink()
                or record.get("sha256") != sha256_file(path)
            ):
                raise PackagingError(f"license hash/path drift: {relative}")
    external_names: set[str] = set()
    for component in external:
        if (
            not isinstance(component, dict)
            or not isinstance(component.get("name"), str)
            or component["name"] in external_names
            or not isinstance(component.get("version"), str)
            or not isinstance(component.get("reason"), str)
        ):
            raise PackagingError("invalid not_redistributed component")
        external_names.add(component["name"])
    if not (licenses_root / "THIRD_PARTY_NOTICES.md").is_file():
        raise PackagingError("THIRD_PARTY_NOTICES.md is required")
    return manifest


def parse_go_mod(path: Path) -> tuple[str, str, dict[str, str]]:
    module = ""
    toolchain = ""
    requirements: dict[str, str] = {}
    in_require = False
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("module "):
            module = line.split(None, 1)[1]
        elif line.startswith("toolchain "):
            toolchain = line.split(None, 1)[1].removeprefix("go")
        elif line == "require (":
            in_require = True
        elif in_require and line == ")":
            in_require = False
        elif line.startswith("require "):
            parts = line.split()
            if len(parts) != 3:
                raise PackagingError(f"unsupported go.mod require line: {line}")
            requirements[parts[1]] = parts[2]
        elif in_require:
            parts = line.split()
            if len(parts) != 2:
                raise PackagingError(f"unsupported go.mod require line: {line}")
            requirements[parts[0]] = parts[1]
    if not module or not toolchain or not requirements:
        raise PackagingError("go.mod module/toolchain/requirements are incomplete")
    return module, toolchain, requirements


def validate_go_metadata(license_manifest: dict[str, Any]) -> dict[str, str]:
    module, toolchain, requirements = parse_go_mod(ROOT / "portable" / "go.mod")
    if module != "github.com/mrcha033/secuway-vpn/portable":
        raise PackagingError("portable Go module path drift")
    components = {
        component["name"]: component
        for component in license_manifest["components"]
    }
    if components.get("Go toolchain and standard library", {}).get(
        "version"
    ) != toolchain:
        raise PackagingError("Go toolchain/license version drift")
    for name, version in requirements.items():
        if components.get(name, {}).get("version") != version:
            raise PackagingError(f"Go module/license version drift: {name}")
    sums = (ROOT / "portable" / "go.sum").read_text(encoding="utf-8")
    for name, version in requirements.items():
        if f"{name} {version} " not in sums:
            raise PackagingError(f"go.sum is missing {name} {version}")
    return requirements


def validate_distribution(catalog: dict[str, Any]) -> dict[str, Any]:
    product = catalog["product"]
    name = product["name"]
    version = product["version"]
    canonical = ROOT / catalog["plugin"]["canonicalSkillPath"]
    plugin_root = ROOT / "plugins" / name
    if canonical != plugin_root / "skills" / name or not canonical.is_dir():
        raise PackagingError("canonical nested skill path drift")
    if (ROOT / "skills" / name).exists():
        raise PackagingError("top-level duplicate skill tree is forbidden")
    if any(
        path.is_file() and path.name.casefold().startswith("readme")
        for path in canonical.rglob("*")
    ):
        raise PackagingError("the canonical skill folder must not gain a README")
    skill_dirs = {
        path.name
        for path in (plugin_root / "skills").iterdir()
        if path.is_dir()
    }
    if skill_dirs != {name}:
        raise PackagingError("plugin must contain exactly one canonical skill")
    repository = product["repository"]
    codex_manifest = load_json(plugin_root / ".codex-plugin" / "plugin.json")
    claude_manifest = load_json(plugin_root / ".claude-plugin" / "plugin.json")
    for label, manifest in (
        ("Codex", codex_manifest),
        ("Claude", claude_manifest),
    ):
        if (
            manifest.get("name") != name
            or manifest.get("version") != version
            or manifest.get("skills") != "./skills/"
            or manifest.get("homepage") != repository
            or manifest.get("repository") != repository
            or manifest.get("license") != "MIT"
        ):
            raise PackagingError(f"{label} plugin manifest metadata drift")
    if (
        codex_manifest.get("interface", {}).get("websiteURL") != repository
        or "hooks" in codex_manifest
        or "apps" in codex_manifest
        or "mcpServers" in codex_manifest
    ):
        raise PackagingError("Codex plugin interface/capability metadata drift")
    codex_market = load_json(ROOT / ".agents/plugins/marketplace.json")
    claude_market = load_json(ROOT / ".claude-plugin/marketplace.json")
    if codex_market.get("name") != name or claude_market.get("name") != name:
        raise PackagingError("marketplace name drift")
    if len(codex_market.get("plugins", [])) != 1:
        raise PackagingError("Codex marketplace must contain exactly one plugin")
    if len(claude_market.get("plugins", [])) != 1:
        raise PackagingError("Claude marketplace must contain exactly one plugin")
    codex_entry = codex_market["plugins"][0]
    claude_entry = claude_market["plugins"][0]
    if (
        codex_entry.get("name") != name
        or codex_entry.get("source")
        != {"source": "local", "path": "./plugins/secuway-vpn"}
        or codex_entry.get("policy")
        != {"installation": "AVAILABLE", "authentication": "ON_INSTALL"}
        or claude_entry.get("name") != name
        or claude_entry.get("source") != "./plugins/secuway-vpn"
        or claude_entry.get("version") != version
        or claude_entry.get("homepage") != repository
        or claude_entry.get("repository") != repository
    ):
        raise PackagingError("marketplace plugin metadata drift")
    root_license = ROOT / "LICENSE"
    plugin_license = plugin_root / "LICENSE"
    if not root_license.read_text(encoding="utf-8").startswith("MIT License\n"):
        raise PackagingError("root MIT LICENSE is missing")
    if (
        not plugin_license.is_file()
        or plugin_license.read_bytes() != root_license.read_bytes()
    ):
        raise PackagingError("plugin MIT LICENSE must match the root LICENSE")
    asset_manifest = validate_asset_manifest(canonical, version)
    license_manifest = validate_license_manifest(canonical, asset_manifest)
    go_requirements = validate_go_metadata(license_manifest)
    for relative, (data, _) in tree_entries(plugin_root).items():
        assert_secret_free(relative, data)
    for path in (
        ROOT / ".agents/plugins/marketplace.json",
        ROOT / ".claude-plugin/marketplace.json",
        DEFAULT_CATALOG,
        ROOT / "LICENSE",
    ):
        assert_secret_free(path.name, path.read_bytes())
    return {
        "canonical": canonical,
        "pluginRoot": plugin_root,
        "assetManifest": asset_manifest,
        "licenseManifest": license_manifest,
        "goRequirements": go_requirements,
    }


def filtered_windows_asset_manifest(
    manifest: dict[str, Any], architecture: str
) -> dict[str, Any]:
    prefix = f"windows-{architecture}/"
    return {
        "schema": manifest["schema"],
        "version": manifest["version"],
        "source": manifest["source"],
        "openvpn": {
            "version": manifest["openvpn"]["version"],
            architecture: manifest["openvpn"][architecture],
        },
        "assets": {
            name: record
            for name, record in manifest["assets"].items()
            if name.startswith(prefix)
        },
    }


def selected_license_components(
    manifest: dict[str, Any], architecture: str
) -> list[dict[str, Any]]:
    prefix = f"windows-{architecture}/"
    selected: list[dict[str, Any]] = []
    for component in manifest["components"]:
        included = [
            item
            for item in component["included_in"]
            if item.startswith(prefix)
        ]
        if included:
            selected.append({**component, "included_in": included})
    return selected


def windows_bundle_entries(
    catalog: dict[str, Any],
    context: dict[str, Any],
    architecture: str,
) -> dict[str, tuple[bytes, int]]:
    if architecture not in ARCHITECTURES:
        raise PackagingError(f"unsupported Windows architecture: {architecture}")
    name = catalog["product"]["name"]
    prefix = f"{name}-windows-{architecture}"
    canonical: Path = context["canonical"]
    entries: dict[str, tuple[bytes, int]] = {
        f"{prefix}/LICENSE": ((ROOT / "LICENSE").read_bytes(), 0o644)
    }
    for script_name in WINDOWS_SCRIPTS:
        path = canonical / "scripts" / script_name
        entries[f"{prefix}/scripts/{script_name}"] = (
            path.read_bytes(),
            normalized_mode(path),
        )
    asset_manifest = filtered_windows_asset_manifest(
        context["assetManifest"], architecture
    )
    entries[f"{prefix}/assets/manifest.json"] = (
        json_bytes(asset_manifest),
        0o644,
    )
    for relative in sorted(asset_manifest["assets"]):
        path = canonical / "assets" / relative
        entries[f"{prefix}/assets/{relative}"] = (
            path.read_bytes(),
            normalized_mode(path),
        )
    selected_components = selected_license_components(
        context["licenseManifest"], architecture
    )
    filtered_licenses = {
        "schema": context["licenseManifest"]["schema"],
        "components": selected_components,
        "not_redistributed": context["licenseManifest"]["not_redistributed"],
    }
    entries[f"{prefix}/licenses/manifest.json"] = (
        json_bytes(filtered_licenses),
        0o644,
    )
    notices = canonical / "licenses" / "THIRD_PARTY_NOTICES.md"
    entries[f"{prefix}/licenses/THIRD_PARTY_NOTICES.md"] = (
        notices.read_bytes(),
        normalized_mode(notices),
    )
    for component in selected_components:
        for record in component["files"]:
            relative = record["path"]
            path = canonical / "licenses" / PurePosixPath(relative)
            entries[f"{prefix}/licenses/{relative}"] = (
                path.read_bytes(),
                normalized_mode(path),
            )
    for member, (data, _) in entries.items():
        assert_secret_free(member, data)
    return entries


def spdx_id(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9.-]+", "-", name).strip("-.")
    return f"SPDXRef-Package-{slug or 'unnamed'}"


def spdx_package(
    *,
    identifier: str,
    name: str,
    version: str,
    download: str = "NOASSERTION",
    declared_license: str = "NOASSERTION",
    comment: str | None = None,
) -> dict[str, Any]:
    package: dict[str, Any] = {
        "SPDXID": identifier,
        "name": name,
        "versionInfo": version,
        "downloadLocation": download,
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": declared_license,
        "copyrightText": "NOASSERTION",
        "supplier": "NOASSERTION",
    }
    if comment:
        package["comment"] = comment
    return package


def build_spdx_document(
    catalog: dict[str, Any],
    context: dict[str, Any],
    runtime_records: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    name = catalog["product"]["name"]
    version = catalog["product"]["version"]
    repository = catalog["product"]["repository"]
    project_id = spdx_id(name)
    packages: list[dict[str, Any]] = []
    project = spdx_package(
        identifier=project_id,
        name=name,
        version=version,
        download=repository,
        declared_license="MIT",
        comment=(
            "Independent portable VPN project. Project-produced Windows "
            "binaries have no publisher-signing assertion."
        ),
    )
    project["homepage"] = repository
    project["primaryPackagePurpose"] = "APPLICATION"
    project["externalRefs"] = [
        {
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": f"pkg:github/mrcha033/secuway-vpn@{version}",
        }
    ]
    packages.append(project)

    component_ids: dict[str, str] = {}
    for component in context["licenseManifest"]["components"]:
        component_name = component["name"]
        identifier = spdx_id(component_name)
        if identifier in {item["SPDXID"] for item in packages}:
            identifier = spdx_id(f"{component_name}-{component['version']}")
        component_ids[component_name] = identifier
        declared = component.get("license", "NOASSERTION")
        if declared not in VALID_DECLARED_LICENSES:
            declared = "NOASSERTION"
        package = spdx_package(
            identifier=identifier,
            name=component_name,
            version=component["version"],
            download=component.get("source_url", "NOASSERTION"),
            declared_license=declared,
            comment=(
                f"Bundled in: {', '.join(component['included_in'])}. "
                f"Source revision: {component.get('revision', 'NOASSERTION')}. "
                f"License metadata: {component.get('license', 'NOASSERTION')}."
            ),
        )
        if component_name.startswith("golang.org/"):
            package["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": (
                        f"pkg:golang/{component_name}@{component['version']}"
                    ),
                }
            ]
        packages.append(package)

    runtime_ids: dict[str, str] = {}
    for architecture in ARCHITECTURES:
        identifier = spdx_id(f"{name}-windows-{architecture}")
        runtime_ids[architecture] = identifier
        record = runtime_records[architecture]
        package = spdx_package(
            identifier=identifier,
            name=f"{name}-windows-{architecture}",
            version=version,
            download=(
                f"{repository}/releases/download/{catalog['releaseTag']}/"
                f"{record['file']}"
            ),
            declared_license="MIT",
            comment=(
                f"Architecture-specific installer bundle for {architecture}; "
                "only the matching PE payload is redistributed."
            ),
        )
        package["primaryPackagePurpose"] = "INSTALL"
        package["packageFileName"] = record["file"]
        package["checksums"] = [
            {"algorithm": "SHA256", "checksumValue": record["sha256"]}
        ]
        packages.append(package)

    external_ids: dict[tuple[str, str], str] = {}
    openvpn = context["assetManifest"]["openvpn"]
    for architecture in ARCHITECTURES:
        identifier = spdx_id(f"OpenVPN-Community-{architecture}")
        external_ids[("OpenVPN Community", architecture)] = identifier
        record = openvpn[architecture]
        package = spdx_package(
            identifier=identifier,
            name=f"OpenVPN Community ({architecture})",
            version=openvpn["version"],
            download=record["url"],
            comment=(
                "External runtime prerequisite downloaded from upstream; "
                "the MSI is not redistributed in these release bundles."
            ),
        )
        package["checksums"] = [
            {"algorithm": "SHA256", "checksumValue": record["sha256"]}
        ]
        packages.append(package)
    for component in context["licenseManifest"]["not_redistributed"]:
        if component["name"] == "OpenVPN Community":
            continue
        identifier = spdx_id(component["name"])
        external_ids[(component["name"], "all")] = identifier
        packages.append(
            spdx_package(
                identifier=identifier,
                name=component["name"],
                version=component["version"],
                comment=(
                    f"External runtime prerequisite; not redistributed. "
                    f"Reason: {component['reason']}."
                ),
            )
        )

    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": project_id,
        }
    ]
    for component in context["licenseManifest"]["components"]:
        relationships.append(
            {
                "spdxElementId": project_id,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": component_ids[component["name"]],
            }
        )
    for architecture in ARCHITECTURES:
        runtime_id = runtime_ids[architecture]
        relationships.append(
            {
                "spdxElementId": runtime_id,
                "relationshipType": "VARIANT_OF",
                "relatedSpdxElement": project_id,
            }
        )
        for component in selected_license_components(
            context["licenseManifest"], architecture
        ):
            relationships.append(
                {
                    "spdxElementId": runtime_id,
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": component_ids[component["name"]],
                }
            )
        relationships.append(
            {
                "spdxElementId": runtime_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": external_ids[
                    ("OpenVPN Community", architecture)
                ],
            }
        )
        openssl_id = external_ids.get(("OpenSSL libcrypto", "all"))
        if openssl_id:
            relationships.append(
                {
                    "spdxElementId": runtime_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": openssl_id,
                }
            )
    packages.sort(key=lambda item: item["SPDXID"])
    relationships.sort(
        key=lambda item: (
            item["spdxElementId"],
            item["relationshipType"],
            item["relatedSpdxElement"],
        )
    )
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name}-{version}",
        "documentNamespace": (
            f"{repository}/releases/download/{catalog['releaseTag']}/"
            f"{catalog['artifacts']['spdxSbom']}"
        ),
        "creationInfo": {
            "created": catalog["spdxCreated"],
            "creators": [
                "Tool: secuway-vpn deterministic release builder",
                "Organization: mrcha033",
            ],
        },
        "documentDescribes": [project_id],
        "packages": packages,
        "relationships": relationships,
    }
    validate_spdx_document(document)
    return document


def validate_spdx_document(document: dict[str, Any]) -> None:
    if (
        document.get("spdxVersion") != "SPDX-2.3"
        or document.get("dataLicense") != "CC0-1.0"
        or document.get("SPDXID") != "SPDXRef-DOCUMENT"
    ):
        raise PackagingError("generated SPDX document header is invalid")
    packages = document.get("packages")
    relationships = document.get("relationships")
    if not isinstance(packages, list) or not isinstance(relationships, list):
        raise PackagingError("generated SPDX packages/relationships are missing")
    identifiers = {package.get("SPDXID") for package in packages}
    if None in identifiers or len(identifiers) != len(packages):
        raise PackagingError("generated SPDX package identifiers are invalid")
    valid_identifiers = identifiers | {"SPDXRef-DOCUMENT"}
    for relationship in relationships:
        if (
            relationship.get("spdxElementId") not in valid_identifiers
            or relationship.get("relatedSpdxElement") not in valid_identifiers
        ):
            raise PackagingError("generated SPDX relationship has unknown ID")


def build_release(
    catalog: dict[str, Any], output: Path, tag: str | None = None
) -> list[Path]:
    if tag is not None and tag != catalog["releaseTag"]:
        raise PackagingError(
            f"release tag {tag!r} must exactly match {catalog['releaseTag']!r}"
        )
    context = validate_distribution(catalog)
    if output.exists() and not output.is_dir():
        raise PackagingError(f"output path is not a directory: {output}")
    if output.exists() and any(output.iterdir()):
        raise PackagingError(
            f"output directory must be empty to prevent stale assets: {output}"
        )
    output.mkdir(parents=True, exist_ok=True)
    artifacts = catalog["artifacts"]
    name = catalog["product"]["name"]

    standalone_zip = output / artifacts["standaloneZip"]
    standalone_entries = tree_entries(context["canonical"], prefix=name)
    standalone_entries[f"{name}/LICENSE"] = (
        (ROOT / "LICENSE").read_bytes(),
        0o644,
    )
    write_archive(standalone_zip, standalone_entries)
    standalone_skill = output / artifacts["standaloneSkill"]
    standalone_skill.write_bytes(standalone_zip.read_bytes())

    plugin_zip = output / artifacts["pluginZip"]
    plugin_entries = tree_entries(context["pluginRoot"])
    write_archive(plugin_zip, plugin_entries)

    runtime_paths: dict[str, Path] = {}
    runtime_records: dict[str, dict[str, Any]] = {}
    for architecture in ARCHITECTURES:
        key = f"windows{architecture.capitalize()}Zip"
        path = output / artifacts[key]
        write_archive(
            path, windows_bundle_entries(catalog, context, architecture)
        )
        runtime_paths[architecture] = path
        runtime_records[architecture] = artifact_record(path)

    sbom_path = output / artifacts["spdxSbom"]
    sbom_data = json_bytes(
        build_spdx_document(catalog, context, runtime_records)
    )
    assert_secret_free(sbom_path.name, sbom_data)
    sbom_path.write_bytes(sbom_data)

    artifact_paths = {
        "standaloneZip": standalone_zip,
        "standaloneSkill": standalone_skill,
        "pluginZip": plugin_zip,
        "windowsAmd64Zip": runtime_paths["amd64"],
        "windowsArm64Zip": runtime_paths["arm64"],
        "spdxSbom": sbom_path,
    }
    artifact_records = {
        key: artifact_record(path)
        for key, path in sorted(artifact_paths.items())
    }
    if (
        artifact_records["standaloneZip"]["sha256"]
        != artifact_records["standaloneSkill"]["sha256"]
    ):
        raise PackagingError("standalone ZIP and .skill must be byte-identical")
    release_manifest = output / "release-manifest.json"
    release_data = json_bytes(
        {
            "schema": "secuway-vpn-release-manifest/v1",
            "product": catalog["product"],
            "plugin": catalog["plugin"],
            "releaseTag": catalog["releaseTag"],
            "provenance": {
                **catalog["provenance"],
                "canonicalTree": {
                    "fileCount": len(relative_files(context["canonical"])),
                    "sha256": tree_sha256(context["canonical"]),
                    "digestAlgorithm": (
                        "SHA-256 over sorted path, normalized mode, and "
                        "per-file SHA-256 records"
                    ),
                },
            },
            "security": {
                "liveTunnelCredentialsIncluded": False,
                "projectBinaryPublisherSigning": "NOT_CLAIMED",
                "archiveSymlinksAllowed": False,
            },
            "artifacts": artifact_records,
        }
    )
    assert_secret_free(release_manifest.name, release_data)
    release_manifest.write_bytes(release_data)

    checksum_targets = sorted(
        [*artifact_paths.values(), release_manifest], key=lambda path: path.name
    )
    checksum_path = output / "SHA256SUMS"
    checksum_data = "".join(
        f"{sha256_file(path)}  {path.name}\n" for path in checksum_targets
    ).encode("utf-8")
    assert_secret_free(checksum_path.name, checksum_data)
    checksum_path.write_bytes(checksum_data)
    return sorted(
        [*artifact_paths.values(), release_manifest, checksum_path],
        key=lambda path: path.name,
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--catalog",
        type=Path,
        default=DEFAULT_CATALOG,
        help="release catalog path",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "dist",
        help="empty output directory for generated assets",
    )
    parser.add_argument(
        "--tag",
        help="require this exact catalog release tag",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        catalog = load_catalog(args.catalog)
        built = build_release(catalog, args.output_dir, tag=args.tag)
    except PackagingError as exc:
        print(f"release packaging: FAIL: {exc}", file=sys.stderr)
        return 1
    for path in built:
        print(f"{sha256_file(path)}  {path}")
    print(
        "release packaging: PASS "
        f"({catalog['product']['name']} {catalog['product']['version']}, "
        f"{len(built)} files)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
