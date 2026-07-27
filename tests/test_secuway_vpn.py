#!/usr/bin/env python3
"""Validate Secuway VPN skill assets, source linkage, and secret boundaries."""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[1]
PRODUCT_VERSION = "0.4.1"
PLUGIN = ROOT / "plugins" / "secuway-vpn"
SKILL = PLUGIN / "skills" / "secuway-vpn"
ASSETS = SKILL / "assets"
LICENSES = SKILL / "licenses"
PLUGIN_MANIFESTS = (
    PLUGIN / ".claude-plugin" / "plugin.json",
    PLUGIN / ".codex-plugin" / "plugin.json",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pe_header(path: Path) -> tuple[int, bool]:
    data = path.read_bytes()
    assert data[:2] == b"MZ", f"{path} is not PE"
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe_offset : pe_offset + 4] == b"PE\0\0"
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    characteristics = struct.unpack_from("<H", data, pe_offset + 22)[0]
    return machine, bool(characteristics & 0x2000)


def pe_linker_version(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_header = pe_offset + 24
    return data[optional_header + 2], data[optional_header + 3]


def main() -> None:
    manifest = json.loads((ASSETS / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema"] == "secuway-windows-assets/v1"
    assert manifest["version"] == PRODUCT_VERSION
    for path in PLUGIN_MANIFESTS:
        plugin_manifest = json.loads(path.read_text(encoding="utf-8"))
        assert plugin_manifest["name"] == "secuway-vpn"
        assert plugin_manifest["version"] == PRODUCT_VERSION
    assert (
        manifest["source"]["provider_source_sha256"]
        == sha256(ROOT / "src" / "lea_provider.cpp")
    )
    assert (
        manifest["source"]["provider_smoke_source_sha256"]
        == sha256(ROOT / "tests" / "provider_smoke.c")
    )
    main_go = (ROOT / "portable" / "cmd" / "secuway" / "main.go").read_text(
        encoding="utf-8"
    )
    provider_source = (ROOT / "src" / "lea_provider.cpp").read_text(
        encoding="utf-8"
    )
    assert f'const version = "{PRODUCT_VERSION}"' in main_go
    assert (
        f'OSSL_PARAM_set_utf8_ptr(p, "{PRODUCT_VERSION}")'
        in provider_source
    )

    expected_machine = {"amd64": 0x8664, "arm64": 0xAA64}
    for relative, record in manifest["assets"].items():
        path = ASSETS / relative
        assert path.is_file(), f"missing asset: {relative}"
        assert path.stat().st_size == record["bytes"]
        assert sha256(path) == record["sha256"]
        architecture = relative.split("/", 1)[0].removeprefix("windows-")
        machine, is_dll = pe_header(path)
        assert machine == expected_machine[architecture]
        assert is_dll == relative.endswith("/lea.dll")

    license_manifest = json.loads(
        (LICENSES / "manifest.json").read_text(encoding="utf-8")
    )
    assert license_manifest["schema"] == "secuway-third-party-licenses/v1"
    expected_components = {
        "Go toolchain and standard library": (
            "1.25.4",
            "f2cd93aa0505465c1d30201c806b6d4d3481c5fa",
        ),
        "golang.org/x/sys": (
            "v0.47.0",
            "9e7e939dcafac07e8ab4cffa6e5fc74908413f00",
        ),
        "golang.org/x/term": (
            "v0.45.0",
            "9f69229da31ca6a34b522f59dbe07cad5ea21587",
        ),
        "Crypto++": (
            "8.9.0",
            "843d74c7c97f9e19a615b8ff3c0ca06599ca501b",
        ),
        "GCC runtime libraries": (
            "12.2.0",
            "2ee5e4300186a92ad73f1a1a64cb918dc76c8d67",
        ),
        "MinGW-w64 runtime (AMD64 build)": (
            "10.0.0",
            "aa08f56da559016f10336dddca85d59f9bdc9e02",
        ),
        "Microsoft Visual C++ static runtime (ARM64 build)": (
            "14.44.35207",
            "vs2022-ga-proenterprise",
        ),
    }
    components = {
        component["name"]: component
        for component in license_manifest["components"]
    }
    assert set(components) == set(expected_components)

    distributed_assets = set(manifest["assets"])
    covered_assets: set[str] = set()
    licensed_files: set[str] = set()
    for name, (version, revision) in expected_components.items():
        component = components[name]
        assert component["version"] == version
        assert component["revision"] == revision
        assert component["source_url"].startswith("https://")
        assert component["license"]
        for relative in component["included_in"]:
            assert relative in distributed_assets
            covered_assets.add(relative)
        for record in component["files"]:
            relative = record["path"]
            assert relative not in licensed_files
            licensed_files.add(relative)
            path = LICENSES / relative
            assert path.is_file(), f"missing third-party text: {relative}"
            assert sha256(path) == record["sha256"]
            if not name.startswith("Microsoft Visual C++"):
                assert revision in record["source_url"]
            assert record["source_url"].startswith("https://")

    assert covered_assets == distributed_assets
    actual_license_files = {
        path.relative_to(LICENSES).as_posix()
        for path in LICENSES.rglob("*")
        if path.is_file()
    } - {"THIRD_PARTY_NOTICES.md", "manifest.json"}
    assert actual_license_files == licensed_files

    go_mod = (ROOT / "portable" / "go.mod").read_text(encoding="utf-8")
    assert go_mod.startswith(
        "module github.com/mrcha033/secuway-vpn/portable\n"
    )
    assert "golang.org/x/sys v0.47.0" in go_mod
    assert "golang.org/x/term v0.45.0" in go_mod
    assert manifest["source"]["go_version"] == "1.25.4"
    for architecture in ("amd64", "arm64"):
        cli = (ASSETS / f"windows-{architecture}" / "secuway.exe").read_bytes()
        for marker in (
            b"go1.25.4",
            b"golang.org/x/sys",
            b"v0.47.0",
            b"golang.org/x/term",
            b"v0.45.0",
        ):
            assert marker in cli

    amd64_provider = (ASSETS / "windows-amd64" / "lea.dll").read_bytes()
    arm64_provider_path = ASSETS / "windows-arm64" / "lea.dll"
    arm64_provider = arm64_provider_path.read_bytes()
    arm64_smoke_path = ASSETS / "windows-arm64" / "provider_smoke.exe"
    arm64_smoke = arm64_smoke_path.read_bytes()
    assert b"GCC: (GNU) 12 20220819" in amd64_provider
    assert b"Mingw-w64 runtime failure:" in amd64_provider
    for obsolete_marker in (
        b"libc++abi:",
        b"libunwind:",
        b"Mingw-w64 runtime failure:",
    ):
        assert obsolete_marker not in arm64_provider
        assert obsolete_marker not in arm64_smoke
    assert pe_linker_version(arm64_provider_path) == (14, 44)
    assert pe_linker_version(arm64_smoke_path) == (14, 44)

    x64_build = (
        ROOT / "experiments" / "windows-x64" / "build.sh"
    ).read_text(encoding="utf-8")
    arm64_vcpkg = json.loads(
        (
            ROOT / "experiments" / "windows-arm64" / "vcpkg.json"
        ).read_text(encoding="utf-8")
    )
    arm64_cmake = (
        ROOT / "experiments" / "windows-arm64" / "CMakeLists.txt"
    ).read_text(encoding="utf-8")
    arm64_triplet = (
        ROOT
        / "experiments"
        / "windows-arm64"
        / "triplets"
        / "arm64-windows-secuway.cmake"
    ).read_text(encoding="utf-8")
    arm64_native_test = (
        ROOT
        / "experiments"
        / "windows-arm64"
        / "test-on-windows.ps1"
    ).read_text(encoding="utf-8")
    arm64_ci = (
        ROOT
        / "experiments"
        / "windows-arm64"
        / "ci"
        / "build-and-test.ps1"
    ).read_text(encoding="utf-8")
    assert "CRYPTOPP_VERSION=8.9.0" in x64_build
    assert "-static-libgcc -static-libstdc++" in x64_build
    assert arm64_vcpkg["version-string"] == PRODUCT_VERSION
    assert arm64_vcpkg["overrides"] == [
        {
            "name": "cryptopp",
            "version": "8.9.0",
            "port-version": 2,
        }
    ]
    assert "find_package(cryptopp 8.9.0 EXACT CONFIG REQUIRED)" in arm64_cmake
    assert '"${CRYPTOPP_INCLUDE_ROOT}/cryptopp"' in arm64_cmake
    assert "MSVC_RUNTIME_LIBRARY" in arm64_cmake
    assert "MultiThreaded$<$<CONFIG:Debug>:Debug>" in arm64_cmake
    assert "set(VCPKG_CRT_LINKAGE static)" in arm64_triplet
    for runtime_name in (
        "libc\\+\\+abi",
        "libunwind",
        "libgcc",
        "libstdc\\+\\+",
        "libwinpthread",
        "msvcp",
        "vcruntime",
    ):
        assert runtime_name in arm64_native_test
    assert "'msvc_crt_linkage=static'" in arm64_ci
    assert "'external_toolchain_runtime_imports=false'" in arm64_ci
    assert arm64_ci.count(
        "for ($attempt = 1; $attempt -le 3; $attempt++)"
    ) == 2
    assert "[switch]$SkipBundledValidation" in arm64_ci
    assert "if (-not $SkipBundledValidation)" in arm64_ci
    assert "'bundled_native_runtime_validated=false'" in arm64_ci
    assert "--filter=blob:none" not in arm64_ci

    microsoft = components[
        "Microsoft Visual C++ static runtime (ARM64 build)"
    ]
    assert microsoft["license"] == (
        "LicenseRef-Microsoft-Visual-Studio-Enterprise-2022"
    )
    assert microsoft["license_name"] == (
        "Microsoft Visual Studio Enterprise 2022 Software License Terms"
    )
    assert microsoft["source_url"] == (
        "https://visualstudio.microsoft.com/license-terms/"
        "vs2022-ga-proenterprise/"
    )
    assert microsoft["terms_url"] == (
        "https://visualstudio.microsoft.com/wp-content/uploads/2021/11/"
        "Visual-Studio-2022-Enterprise-Professional-License-EN.docx"
    )
    assert microsoft["redistribution_url"] == (
        "https://learn.microsoft.com/en-us/visualstudio/releases/2022/"
        "redistribution"
    )
    assert microsoft["crt_documentation_url"] == (
        "https://learn.microsoft.com/en-us/cpp/c-runtime-library/"
        "crt-library-features?view=msvc-170"
    )
    assert microsoft["build_toolchain"] == {
        "name": "Microsoft Visual C++ v143",
        "github_runner": "windows-11-arm",
        "github_runner_image_version": "20260719.114.1",
        "visual_studio_edition": "Enterprise",
        "visual_studio_version": "17.14.36",
        "vctools_version": "14.44.35207",
        "compiler_version": "19.44.35228.0",
        "linker_version": "14.44",
        "windows_sdk_version": "10.0.26100.0",
        "runtime_linkage": "/MT (static)",
    }
    assert microsoft["static_runtime_scope"] == {
        "windows-arm64/lea.dll": [
            "libcmt.lib",
            "libvcruntime.lib",
            "libucrt.lib",
            "libcpmt.lib",
        ],
        "windows-arm64/provider_smoke.exe": [
            "libcmt.lib",
            "libvcruntime.lib",
            "libucrt.lib",
        ],
    }
    microsoft_terms = (
        LICENSES
        / "microsoft"
        / "Visual-Studio-2022-Enterprise-Professional-License-EN.docx"
    )
    assert sha256(microsoft_terms) == (
        "9c0cd52b20db9d081854c75bd1b50c75514b8f8cb09c8cad15e89d90b97b5bf3"
    )
    with zipfile.ZipFile(microsoft_terms) as archive:
        terms_xml = archive.read("word/document.xml")
    terms_text = "".join(ElementTree.fromstring(terms_xml).itertext())
    assert "MICROSOFT VISUAL STUDIO ENTERPRISE 2022" in terms_text
    assert "DISTRIBUTABLE CODE" in terms_text

    required_text = {
        "go/LICENSE": "Copyright 2009 The Go Authors.",
        "go/PATENTS": "Additional IP Rights Grant (Patents)",
        "cryptopp/LICENSE.txt": "Boost Software License - Version 1.0",
        "gcc/COPYING3": "GNU GENERAL PUBLIC LICENSE",
        "gcc/COPYING.RUNTIME": "GCC RUNTIME LIBRARY EXCEPTION",
        "mingw-w64/amd64-COPYING.MinGW-w64-runtime.txt": (
            "MinGW-w64 runtime licensing"
        ),
    }
    for relative, marker in required_text.items():
        text = (LICENSES / relative).read_text(encoding="utf-8")
        assert marker in text
    assert "Version 3.1, 31 March 2009" in (
        LICENSES / "gcc" / "COPYING.RUNTIME"
    ).read_text(encoding="utf-8")
    assert "CRYPTOGAMS License" in (
        LICENSES / "cryptopp" / "LICENSE.txt"
    ).read_text(encoding="utf-8")

    notices = (LICENSES / "THIRD_PARTY_NOTICES.md").read_text(
        encoding="utf-8"
    )
    for marker in (
        "Go 1.25.4",
        "Crypto++ 8.9.0",
        "GCC 12.2.0",
        "MinGW-w64 10.0.0",
        "Visual Studio 2022 Enterprise `17.14.36`",
        "VCTools `14.44.35207`",
        "MSVC `19.44.35228.0`",
        "SDK `10.0.26100.0`",
        "`/MT`",
        "OpenVPN Community `2.7.5-I001`",
        "redistributed in this skill",
    ):
        assert marker in notices
    assert license_manifest["not_redistributed"] == [
        {
            "name": "OpenVPN Community",
            "version": "2.7.5-I001",
            "reason": (
                "downloaded from and installed from the official upstream MSI"
            ),
        },
        {
            "name": "OpenSSL libcrypto",
            "version": "3.6.3",
            "reason": (
                "dynamically supplied by the separately installed official "
                "OpenVPN package"
            ),
        },
    ]

    assert (SKILL / "scripts" / "Install-WindowsRuntime.ps1").read_bytes() == (
        ROOT / "experiments" / "windows-ci" / "Install-Windows.ps1"
    ).read_bytes()

    skill_text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    setup_text = (SKILL / "scripts" / "Setup-Windows.ps1").read_text(
        encoding="utf-8"
    )
    runtime_text = (
        SKILL / "scripts" / "Install-WindowsRuntime.ps1"
    ).read_text(encoding="utf-8")
    reference_text = (SKILL / "references" / "platforms.md").read_text(
        encoding="utf-8"
    )
    assert "[TODO:" not in skill_text
    assert "licenses/THIRD_PARTY_NOTICES.md" in skill_text
    assert "cannot be replaced or" in reference_text
    for marker in (
        "ssh -tt user@host",
        "AUTHENTICATION_FACTOR_UNAVAILABLE",
        "outcome as `BLOCKED`",
        "Never copy a macOS Keychain item",
        "directly visible session",
    ):
        assert marker in skill_text
    for marker in (
        "## Enrollment host matrix",
        "ssh -tt user@host",
        "task outcome `BLOCKED`",
        "Do not move protected enrollment between hosts",
    ):
        assert marker in reference_text
    assert "OpenVPNServiceInteractive" in runtime_text
    assert "Get-AuthenticodeSignature" in setup_text
    assert "TargetSid" in setup_text
    assert "secrets_printed = $false" in setup_text
    assert f'version = "{PRODUCT_VERSION}"' in setup_text

    forbidden = (
        "QTA_KIS_APP_KEY=",
        "QTA_KIS_APP_SECRET=",
        "BEGIN PRIVATE KEY",
    )
    for path in list(SKILL.rglob("*.md")) + list(SKILL.rglob("*.ps1")):
        text = path.read_text(encoding="utf-8")
        for marker in forbidden:
            assert marker not in text, f"forbidden material in {path}: {marker}"

    result = subprocess.run(
        [
            sys.executable,
            str(SKILL / "scripts" / "secuway_status.py"),
            "--self-test",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "PASS" in result.stdout
    print("Secuway VPN skill and Windows assets: PASS")


if __name__ == "__main__":
    main()
