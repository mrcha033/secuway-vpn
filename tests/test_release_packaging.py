#!/usr/bin/env python3
"""Validate deterministic standalone, plugin, Windows, and SPDX assets."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_release_packages import (  # noqa: E402
    ARCHITECTURES,
    FIXED_ZIP_TIME,
    PackagingError,
    build_release,
    load_catalog,
    relative_files,
    selected_license_components,
    sha256_file,
    tree_sha256,
    validate_distribution,
)

NAME = "secuway-vpn"
VERSION = "0.4.1"
SKILL = ROOT / "plugins/secuway-vpn/skills/secuway-vpn"
PLUGIN = ROOT / "plugins/secuway-vpn"
WINDOWS_SCRIPTS = {"Install-WindowsRuntime.ps1", "Setup-Windows.ps1"}


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def archive_files(path: Path) -> dict[str, tuple[bytes, int]]:
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        assert names == sorted(names)
        assert len(names) == len(set(names))
        result: dict[str, tuple[bytes, int]] = {}
        for info in infos:
            pure = PurePosixPath(info.filename)
            assert not pure.is_absolute()
            assert ".." not in pure.parts
            assert "\\" not in info.filename
            assert not info.is_dir()
            assert info.date_time == FIXED_ZIP_TIME
            assert info.compress_type == zipfile.ZIP_STORED
            mode = (info.external_attr >> 16) & 0o777
            assert mode in {0o644, 0o755}
            result[info.filename] = (archive.read(info), mode)
        return result


def expected_tree(
    root: Path, prefix: str = ""
) -> dict[str, tuple[bytes, int]]:
    return {
        (
            PurePosixPath(prefix) / PurePosixPath(relative.as_posix())
        ).as_posix(): (
            (root / relative).read_bytes(),
            0o755 if (root / relative).stat().st_mode & 0o111 else 0o644,
        )
        for relative in relative_files(root)
    }


def pe_information(data: bytes) -> tuple[int, bool]:
    assert data[:2] == b"MZ"
    offset = int.from_bytes(data[0x3C:0x40], "little")
    assert data[offset : offset + 4] == b"PE\0\0"
    machine = int.from_bytes(data[offset + 4 : offset + 6], "little")
    characteristics = int.from_bytes(data[offset + 22 : offset + 24], "little")
    return machine, bool(characteristics & 0x2000)


def assert_archive_secret_free(
    contents: dict[str, tuple[bytes, int]]
) -> None:
    forbidden_suffixes = {
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
    markers = (
        b"-----BEGIN " + b"PRIVATE KEY-----",
        b"-----BEGIN RSA " + b"PRIVATE KEY-----",
        b"-----BEGIN " + b"CERTIFICATE-----",
    )
    for name, (data, _) in contents.items():
        assert PurePosixPath(name).suffix.casefold() not in forbidden_suffixes
        for marker in markers:
            assert marker not in data, f"secret marker in {name}"


def validate_windows_bundle(
    path: Path,
    architecture: str,
    context: dict,
) -> None:
    contents = archive_files(path)
    assert_archive_secret_free(contents)
    prefix = f"{NAME}-windows-{architecture}"
    assert {PurePosixPath(name).parts[0] for name in contents} == {prefix}
    assert not any(
        PurePosixPath(name).name.casefold().startswith("readme")
        for name in contents
    )
    assert contents[f"{prefix}/LICENSE"][0] == (ROOT / "LICENSE").read_bytes()
    scripts = {
        PurePosixPath(name).name
        for name in contents
        if name.startswith(f"{prefix}/scripts/")
    }
    assert scripts == WINDOWS_SCRIPTS
    for script in WINDOWS_SCRIPTS:
        assert contents[f"{prefix}/scripts/{script}"][0] == (
            SKILL / "scripts" / script
        ).read_bytes()

    asset_manifest = json.loads(
        contents[f"{prefix}/assets/manifest.json"][0].decode("utf-8")
    )
    expected_asset_paths = {
        f"windows-{architecture}/{filename}"
        for filename in ("lea.dll", "provider_smoke.exe", "secuway.exe")
    }
    assert set(asset_manifest["assets"]) == expected_asset_paths
    assert set(asset_manifest["openvpn"]) == {"version", architecture}
    bundled_pe = {
        name.removeprefix(f"{prefix}/assets/")
        for name in contents
        if name.lower().endswith((".dll", ".exe"))
    }
    assert bundled_pe == expected_asset_paths
    expected_machine = {"amd64": 0x8664, "arm64": 0xAA64}[architecture]
    for relative, record in asset_manifest["assets"].items():
        member = f"{prefix}/assets/{relative}"
        data = contents[member][0]
        assert record == {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        machine, is_dll = pe_information(data)
        assert machine == expected_machine
        assert is_dll == relative.endswith(".dll")

    license_manifest = json.loads(
        contents[f"{prefix}/licenses/manifest.json"][0].decode("utf-8")
    )
    expected_components = selected_license_components(
        context["licenseManifest"], architecture
    )
    assert license_manifest["components"] == expected_components
    assert license_manifest["not_redistributed"] == (
        context["licenseManifest"]["not_redistributed"]
    )
    expected_license_members = {
        f"{prefix}/licenses/manifest.json",
        f"{prefix}/licenses/THIRD_PARTY_NOTICES.md",
    }
    for component in license_manifest["components"]:
        assert component["included_in"]
        assert set(component["included_in"]) <= set(asset_manifest["assets"])
        assert all(
            item.startswith(f"windows-{architecture}/")
            for item in component["included_in"]
        )
        for record in component["files"]:
            member = f"{prefix}/licenses/{record['path']}"
            expected_license_members.add(member)
            assert member in contents
            assert hashlib.sha256(contents[member][0]).hexdigest() == (
                record["sha256"]
            )
    actual_license_members = {
        name
        for name in contents
        if name.startswith(f"{prefix}/licenses/")
    }
    assert actual_license_members == expected_license_members

    expected_members = {
        f"{prefix}/LICENSE",
        f"{prefix}/assets/manifest.json",
        *(f"{prefix}/assets/{item}" for item in expected_asset_paths),
        *(f"{prefix}/scripts/{item}" for item in WINDOWS_SCRIPTS),
        *expected_license_members,
    }
    assert set(contents) == expected_members


def validate_spdx(
    path: Path,
    catalog: dict,
    context: dict,
    runtime_paths: dict[str, Path],
) -> None:
    document = load_json(path)
    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["dataLicense"] == "CC0-1.0"
    assert document["SPDXID"] == "SPDXRef-DOCUMENT"
    created = datetime.fromisoformat(
        document["creationInfo"]["created"].replace("Z", "+00:00")
    )
    assert created.tzinfo is not None
    assert created <= datetime.now(timezone.utc)
    assert document["creationInfo"]["created"] == catalog["spdxCreated"]

    packages = {package["name"]: package for package in document["packages"]}
    assert len(packages) == len(document["packages"])
    project = packages[NAME]
    assert project["versionInfo"] == VERSION
    assert project["licenseDeclared"] == "MIT"
    assert "no publisher-signing assertion" in project["comment"]
    for component in context["licenseManifest"]["components"]:
        package = packages[component["name"]]
        assert package["versionInfo"] == component["version"]
        assert component["name"] in packages
    for module, version in context["goRequirements"].items():
        assert packages[module]["versionInfo"] == version
        assert packages[module]["externalRefs"][0]["referenceLocator"] == (
            f"pkg:golang/{module}@{version}"
        )
    assert "OpenVPN Community (amd64)" in packages
    assert "OpenVPN Community (arm64)" in packages
    assert "OpenSSL libcrypto" in packages

    relationships = {
        (
            relation["spdxElementId"],
            relation["relationshipType"],
            relation["relatedSpdxElement"],
        )
        for relation in document["relationships"]
    }
    project_id = project["SPDXID"]
    assert ("SPDXRef-DOCUMENT", "DESCRIBES", project_id) in relationships
    for architecture in ARCHITECTURES:
        runtime = packages[f"{NAME}-windows-{architecture}"]
        runtime_path = runtime_paths[architecture]
        assert runtime["versionInfo"] == VERSION
        assert runtime["packageFileName"] == runtime_path.name
        assert runtime["checksums"] == [
            {"algorithm": "SHA256", "checksumValue": sha256_file(runtime_path)}
        ]
        assert (runtime["SPDXID"], "VARIANT_OF", project_id) in relationships
        expected_components = selected_license_components(
            context["licenseManifest"], architecture
        )
        for component in expected_components:
            assert (
                runtime["SPDXID"],
                "CONTAINS",
                packages[component["name"]]["SPDXID"],
            ) in relationships
        assert (
            runtime["SPDXID"],
            "DEPENDS_ON",
            packages[f"OpenVPN Community ({architecture})"]["SPDXID"],
        ) in relationships
        assert (
            runtime["SPDXID"],
            "DEPENDS_ON",
            packages["OpenSSL libcrypto"]["SPDXID"],
        ) in relationships


def snapshot(path: Path) -> dict[str, tuple[int, str]]:
    return {
        item.name: (item.stat().st_size, sha256_file(item))
        for item in path.iterdir()
        if item.is_file()
    }


def validate_release_workflow() -> None:
    workflow = (
        ROOT / ".github/workflows/release.yml"
    ).read_text(encoding="utf-8")
    assert 'gh release view "$GITHUB_REF_NAME" --json assets' in workflow
    assert (
        "releases/tags/${GITHUB_REF_NAME}" not in workflow
    ), "draft releases are not available through the tag-addressed REST route"


def main() -> None:
    validate_release_workflow()
    catalog = load_catalog()
    context = validate_distribution(catalog)
    try:
        with tempfile.TemporaryDirectory(prefix="secuway-stale.") as temporary:
            stale = Path(temporary)
            (stale / "old.zip").write_bytes(b"stale")
            build_release(catalog, stale, tag=catalog["releaseTag"])
    except PackagingError:
        pass
    else:
        raise AssertionError("non-empty output must fail closed")
    try:
        with tempfile.TemporaryDirectory(prefix="secuway-tag.") as temporary:
            build_release(catalog, Path(temporary), tag="v999.0.0")
    except PackagingError:
        pass
    else:
        raise AssertionError("mismatched release tag must fail closed")

    with tempfile.TemporaryDirectory(prefix="secuway-release-a.") as temporary:
        first = Path(temporary)
        built = build_release(catalog, first, tag=catalog["releaseTag"])
        expected_names = {
            *catalog["artifacts"].values(),
            "release-manifest.json",
            "SHA256SUMS",
        }
        assert {path.name for path in built} == expected_names
        assert {path.name for path in first.iterdir()} == expected_names

        standalone_zip = first / catalog["artifacts"]["standaloneZip"]
        standalone_skill = first / catalog["artifacts"]["standaloneSkill"]
        plugin_zip = first / catalog["artifacts"]["pluginZip"]
        assert standalone_zip.read_bytes() == standalone_skill.read_bytes()
        standalone_contents = archive_files(standalone_zip)
        expected_standalone = expected_tree(SKILL, NAME)
        expected_standalone[f"{NAME}/LICENSE"] = (
            (ROOT / "LICENSE").read_bytes(),
            0o644,
        )
        assert standalone_contents == expected_standalone
        assert_archive_secret_free(standalone_contents)
        assert archive_files(plugin_zip) == expected_tree(PLUGIN)
        assert archive_files(plugin_zip)["LICENSE"][0] == (
            ROOT / "LICENSE"
        ).read_bytes()

        runtime_paths = {
            "amd64": first / catalog["artifacts"]["windowsAmd64Zip"],
            "arm64": first / catalog["artifacts"]["windowsArm64Zip"],
        }
        for architecture, path in runtime_paths.items():
            validate_windows_bundle(path, architecture, context)
        validate_spdx(
            first / catalog["artifacts"]["spdxSbom"],
            catalog,
            context,
            runtime_paths,
        )

        release_manifest = load_json(first / "release-manifest.json")
        assert release_manifest["schema"] == (
            "secuway-vpn-release-manifest/v1"
        )
        assert release_manifest["product"]["version"] == VERSION
        assert release_manifest["plugin"]["version"] == VERSION
        assert release_manifest["releaseTag"] == f"v{VERSION}"
        assert release_manifest["provenance"]["commit"] == (
            "4e9b843bfcf434be9d76829355f0eee34939bc41"
        )
        assert release_manifest["provenance"]["canonicalTree"] == {
            "fileCount": len(relative_files(SKILL)),
            "sha256": tree_sha256(SKILL),
            "digestAlgorithm": (
                "SHA-256 over sorted path, normalized mode, and per-file "
                "SHA-256 records"
            ),
        }
        assert release_manifest["security"] == {
            "liveTunnelCredentialsIncluded": False,
            "projectBinaryPublisherSigning": "NOT_CLAIMED",
            "archiveSymlinksAllowed": False,
        }
        assert set(release_manifest["artifacts"]) == set(catalog["artifacts"])
        for key, filename in catalog["artifacts"].items():
            path = first / filename
            assert release_manifest["artifacts"][key] == {
                "file": filename,
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }

        checksum_lines = (
            first / "SHA256SUMS"
        ).read_text(encoding="utf-8").splitlines()
        checksums = dict(line.split("  ", 1)[::-1] for line in checksum_lines)
        assert set(checksums) == expected_names - {"SHA256SUMS"}
        for filename, digest in checksums.items():
            assert digest == sha256_file(first / filename)
        first_snapshot = snapshot(first)

    # Build sequentially so determinism checking never retains two large dists.
    with tempfile.TemporaryDirectory(prefix="secuway-release-b.") as temporary:
        second = Path(temporary)
        build_release(catalog, second, tag=catalog["releaseTag"])
        assert snapshot(second) == first_snapshot

    print(
        "deterministic release packaging: PASS "
        "(3 portable archives, 2 Windows bundles, SPDX 2.3)"
    )


if __name__ == "__main__":
    main()
