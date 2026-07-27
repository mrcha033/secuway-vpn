---
name: secuway-vpn
description: Install, diagnose, enroll, connect, and remove a portable SecuwaySSL-compatible VPN runtime on Windows amd64/arm64, macOS, or Linux while preserving one-time server-approved authentication and strict secret handling. Use when a user asks about Secuway/SecuwaySSL VPN availability, Windows support, OTP and cached enrollment, remote or headless server bootstrap through an SSH TTY, unavailable authentication factors, OpenVPN LEA compatibility, VPN access to a remote or internal host, or errors from the secuway CLI.
---

# Secuway VPN

Operate the VPN on the host that needs protected-network access. Preserve the
gateway's authentication policy: cache only a successful server-issued profile,
never a password, OTP value, or OTP seed. Do not use a different Mac or Windows
host as an implicit VPN boundary and do not move a protected profile cache
between hosts.

Read [references/platforms.md](references/platforms.md) before platform setup,
enrollment, removal, or a live-tunnel claim.

## Inspect first

Resolve this skill directory. On Windows, inspect the installation without
requiring Python:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  "scripts\Setup-Windows.ps1" -Action Status
```

If `secuway.exe` is installed, also run `secuway status --json` to distinguish
cached enrollment from `NEEDS_ENROLLMENT`.

On macOS or Linux, run the read-only helper:

```sh
python3 scripts/secuway_status.py
```

Use `--cli <path>` when discovery misses an existing installation and
`--server https://host` for a non-default gateway. Report the helper's exact
status boundary. In particular, do not equate a cached profile with a live
login or tunnel.

## Install Windows support

Run installation only when the user asks to install, configure, or connect and
the read-only status shows that setup is needed:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  "scripts\Setup-Windows.ps1" -Action Install
```

The bundled setup selects amd64 or arm64 assets, verifies every bundled hash,
and installs the pinned, signed official OpenVPN Community MSI only when
OpenVPN is absent. It preserves the original caller SID through one UAC
approval, installs the LEA provider, protects the per-user profile directory,
and enables ordinary connections through OpenVPN Interactive Service.
The exact third-party versions, source revisions, and unmodified license,
patent, credit, and runtime-notice texts for the bundled binaries are in
[licenses/THIRD_PARTY_NOTICES.md](licenses/THIRD_PARTY_NOTICES.md).

After setup, rerun the Windows `Setup-Windows.ps1 -Action Status` command and
`secuway status --json`. Treat local `doctor` success as runtime evidence only.

## Enroll and connect

Start `secuway connect` in a terminal directly visible to the user. Allow the
CLI to prompt locally. Do not request or relay the user's ID, password, app OTP,
OTP seed, certificate, private key, or profile through chat. Do not place those
values in arguments, environment variables, files, logs, or automation inputs.

For a remote macOS or Linux host, attach a real terminal to the process:

```sh
ssh -tt user@host 'secuway doctor && secuway status --json && secuway connect'
```

Treat `ssh -tt` only as the interactive terminal transport. Have the user type
each requested factor directly into that attached terminal. Do not run first
enrollment through a scheduler, background job, redirected stdin, CI secret, or
agent-controlled automation. On Windows, use a directly visible session for
the target user, such as Windows Terminal or RDP, so the resulting DPAPI cache
belongs to that user on that machine.

Reuse `CACHED` only while the server-issued profile remains valid. If the
gateway requires OTP and no cached profile exists, an OTP cannot be replaced or
bypassed. Preserve the CLI state as `NEEDS_ENROLLMENT` and report the task
outcome as `BLOCKED` with reason `AUTHENTICATION_FACTOR_UNAVAILABLE` when the
user cannot produce a required factor. Resume only after the user obtains a
gateway-approved authenticator, recovery path, certificate, or service identity.

Never copy a macOS Keychain item, Windows DPAPI blob, or Linux protected profile
from another host as a substitute for enrollment. Cross-host portability,
device binding, and server authorization are not established by local file
access. Use an operator-issued non-interactive credential only when the gateway
operator explicitly supports it for that target host.

On Windows, do not use `login --output`: the CLI refuses plaintext profile
export because POSIX mode `0600` is not a Windows DACL. Use the user-scoped
DPAPI cache and `secuway connect`. The CLI also refuses `connect --config` on
Windows so an arbitrary user-controlled profile cannot cross the Interactive
Service privilege boundary.

Keep the connection process attached unless the user's workflow explicitly
requires a managed background service. On Windows, do not ask for per-connection
elevation after setup; a prompt indicates a setup or service problem.

## Prove live access

Require OpenVPN completion, the tunnel interface, the protected route, and a
bounded probe to the intended internal endpoint before reporting success. For a
remote server workflow, verify the route and endpoint from that same host. Do
not silently substitute a Mac boundary host or an SSH hop.

## Forget or remove

Use `secuway forget` only when the user asks to discard cached enrollment.
Explain that the next connection will require server authentication again.

Run Windows removal only after explicit confirmation because it irreversibly
deletes the local cached tunnel profile:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  "scripts\Setup-Windows.ps1" -Action Uninstall
```

Leave official OpenVPN installed. Never claim that local deletion revoked the
gateway certificate.
