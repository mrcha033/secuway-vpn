#!/usr/bin/env python3
"""Guard the Windows privilege, rollback, and native-CI boundaries."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = (
    ROOT / "plugins" / "secuway-vpn" / "skills" / "secuway-vpn"
)
WORKFLOWS = (
    ROOT / ".github" / "workflows" / "secuway-windows-portable.yml",
    ROOT / ".github" / "workflows" / "secuway-windows-x64-provider.yml",
    ROOT / ".github" / "workflows" / "secuway-windows-arm64-provider.yml",
    ROOT / ".github" / "workflows" / "refresh-native-assets.yml",
)
FORBIDDEN_PUBLIC_TUNNEL_WORKFLOWS = (
    ROOT / ".github" / "workflows" / "secuway-windows-tunnel.yml",
    ROOT
    / "experiments"
    / "windows-ci"
    / "windows-tunnel-self-hosted.yml",
)
FORBIDDEN_DUPLICATE_WORKFLOW_TEMPLATES = (
    ROOT / "experiments" / "windows-ci" / "windows-portable.yml",
    ROOT
    / "experiments"
    / "windows-arm64"
    / "workflow"
    / "windows-arm64.yml",
)


def main() -> None:
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert "*.c text eol=lf" in attributes
    assert "*.cpp text eol=lf" in attributes

    setup = (SKILL / "scripts" / "Setup-Windows.ps1").read_text()
    transaction = setup.index("$runtimeStateBefore = Get-ExistingRuntimeState")
    doctor = setup.index("& $change.Destination doctor", transaction)
    commit = setup.index("Complete-UserCliInstall", transaction)
    assert doctor < commit, "CLI state was committed before doctor"
    assert "Windows runtime rollback failed" in setup
    assert "Write-AtomicJson -Path $Change.StatePath -Value $Change.ExistingState" in setup

    runtime = (
        SKILL / "scripts" / "Install-WindowsRuntime.ps1"
    ).read_text()
    assert "if (-not [bool]$state.service_was_running)" in runtime
    assert "Stop-Service -Name $serviceName" in runtime
    assert "Start-Service -Name $serviceName -ErrorAction SilentlyContinue" in runtime
    assert (
        "\n            (Get-ChildItem -LiteralPath $baseDirectory -Force).Count"
        not in runtime
    )
    assert (
        "\n    (Get-ChildItem -LiteralPath $TargetBin -Force).Count"
        not in setup
    )
    assert "path_before_install = $pathBeforeInstall" in setup
    assert "path_after_install = $pathAfterInstall" in setup
    assert "User PATH changed since installation; refusing to overwrite it" in setup
    assert "TargetSid must identify the current user" in setup
    assert '($remaining -join ";")' not in setup
    assert runtime.rstrip().endswith("exit 0")

    engine = (
        ROOT / "portable" / "internal" / "engine" / "engine.go"
    ).read_text()
    windows_engine = (
        ROOT / "portable" / "internal" / "engine" / "command_windows.go"
    ).read_text()
    assert "if goos == \"windows\"" in engine
    assert "never execute a sibling or PATH-provided binary" in engine
    assert "never from the invoking user's" in engine
    assert 'filepath.Join(installDirectory, "bin", "openvpn.exe")' in windows_engine
    assert 'filepath.Join(installDirectory, "ssl", "modules")' in windows_engine
    assert 'GetStringValue("exe_path")' not in windows_engine

    main_go = (
        ROOT / "portable" / "cmd" / "secuway" / "main.go"
    ).read_text()
    connect_case = main_go.index('case "connect":')
    reject = main_go.index("validateConnectConfig", connect_case)
    discover = main_go.index("engine.Discover", connect_case)
    assert reject < discover
    assert "Windows에서는 login --output을 지원하지 않습니다" in main_go
    assert "Windows에서는 connect --config를 지원하지 않습니다" in main_go

    action_pin = re.compile(
        r"(?:-\s+)?uses:\s+[^@\s]+@[0-9a-f]{40}(?:\s+#.*)?$"
    )
    workflow_text = {}
    for path in WORKFLOWS:
        text = path.read_text()
        workflow_text[path.name] = text
        uses = [line.strip() for line in text.splitlines() if "uses:" in line]
        assert uses and all(action_pin.fullmatch(line) for line in uses), path
        assert "self-hosted" not in text, path

    for path in FORBIDDEN_PUBLIC_TUNNEL_WORKFLOWS:
        assert not path.exists(), (
            "public self-hosted tunnel workflows are forbidden; "
            f"use the local harness or a private ops repository: {path}"
        )
    for path in FORBIDDEN_DUPLICATE_WORKFLOW_TEMPLATES:
        assert not path.exists(), (
            "root .github workflows are authoritative; "
            f"remove the duplicate experiment template: {path}"
        )

    portable = workflow_text["secuway-windows-portable.yml"]
    assert '"portable/**"' in portable
    assert '"experiments/windows-ci/**"' in portable
    assert (
        '"plugins/secuway-vpn/skills/secuway-vpn/**"' in portable
    )
    assert "Setup-Windows.ps1" in portable
    assert "windows-11-arm" in portable

    x64 = workflow_text["secuway-windows-x64-provider.yml"]
    assert '"src/lea_provider.cpp"' in x64
    assert '"experiments/windows-x64/**"' in x64
    assert '"plugins/secuway-vpn/skills/secuway-vpn/**"' in x64
    assert "-Action Install" in x64 and "-Action Uninstall" in x64

    arm64 = workflow_text["secuway-windows-arm64-provider.yml"]
    assert '"src/lea_provider.cpp"' in arm64
    assert '"experiments/windows-arm64/**"' in arm64
    assert (
        '"plugins/secuway-vpn/skills/secuway-vpn/assets/**"' in arm64
    )
    for pinned_input in (
        "sdk: 10.0.26100.0",
        "toolset: 14.44",
        "vsversion: 2022",
    ):
        assert pinned_input in arm64
        assert pinned_input in workflow_text["refresh-native-assets.yml"]
    arm64_script = (
        ROOT / "experiments" / "windows-arm64" / "ci" / "build-and-test.ps1"
    ).read_text()
    assert "provider source hash does not match the asset manifest" in arm64_script
    assert "provider smoke source hash does not match the asset manifest" in arm64_script
    assert "$ExpectedMsvcToolsVersion = '14.44.35207'" in arm64_script
    assert "$ExpectedWindowsSdkVersion = '10.0.26100.0'" in arm64_script

    refresh = workflow_text["refresh-native-assets.yml"]
    trigger = refresh.split("permissions:", 1)[0]
    assert "workflow_dispatch:" in trigger
    assert "\n  push:" not in trigger
    assert "\n  pull_request:" not in trigger
    assert "source_sha:" in trigger and "required: true" in trigger
    assert "-SkipBundledValidation" in refresh
    assert "candidate" in refresh

    print("Secuway Windows security and CI boundaries: PASS")


if __name__ == "__main__":
    main()
