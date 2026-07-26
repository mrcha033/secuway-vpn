# Secuway VPN

Version `0.4.0` is a portable, independent SecuwaySSL-compatible enrollment and
OpenVPN launcher for macOS, Linux, and Windows on amd64 and arm64. It does not
invoke or redistribute vendor client binaries.

The CLI performs the gateway's supported authentication flow, validates the
returned profile, stores only that server-issued profile, and reuses it until
the server expires or revokes it. Passwords, OTP values, and OTP seeds are
never cached.

## Runtime model

| Platform | Profile store | Tunnel elevation |
| --- | --- | --- |
| macOS | Login Keychain | `sudo` for OpenVPN |
| Linux | User-owned mode-0600 file | `sudo` for OpenVPN |
| Windows | Current-user DPAPI | One-time UAC setup, then OpenVPN Interactive Service |

Windows setup installs the LEA provider beside an official OpenVPN Community
installation and provisions a per-user profile directory under OpenVPN's
registered `config_dir`. The connection process then runs as the caller; only
route, adapter, and DNS operations cross the official privileged service.

## CLI

```text
secuway doctor
secuway probe
secuway status --json
secuway login
secuway connect
secuway forget
```

Run enrollment in an interactive terminal. Do not place an ID, password, OTP,
profile, or private key in command-line arguments, environment variables,
automation inputs, logs, or chat messages.

## Install the agent plugin

The repository is a one-plugin marketplace named `secuway-vpn`. Both
marketplaces resolve the same self-contained local source,
`./plugins/secuway-vpn`.

### Codex

```sh
codex plugin marketplace add mrcha033/secuway-vpn
codex plugin add secuway-vpn@secuway-vpn
```

Start a new Codex task after installation and invoke `$secuway-vpn`.

### Claude Code

```sh
claude plugin marketplace add mrcha033/secuway-vpn
claude plugin install secuway-vpn@secuway-vpn
```

Run `/reload-plugins` in an active session, then invoke
`/secuway-vpn:secuway-vpn`.

The only canonical Agent Skill distribution tree is
`plugins/secuway-vpn/skills/secuway-vpn/`. There is intentionally no duplicate
top-level `skills/secuway-vpn` tree.

## Build and test

The portable CLI:

```sh
cd portable
go test ./...
go test -race ./...
./scripts/build-cli.sh
```

The reproducible Windows x64 provider build and official OpenVPN runtime check:

```sh
./experiments/windows-x64/build.sh
./experiments/windows-x64/verify-wine.sh
```

The Windows ARM64 provider can be cross-built from macOS:

```sh
./experiments/windows-arm64/build-macos.sh
```

Native Windows x64/ARM64 DPAPI tests and provider checks run in the repository
workflows. A real tunnel test is deliberately separate because it requires a
user-owned, pre-enrolled profile and a host with campus reachability.

## Deterministic release packages

Build every release asset into an empty directory:

```sh
python3 -B scripts/build_release_packages.py \
  --tag v0.4.0 \
  --output-dir dist
```

The builder uses sorted archive members, fixed ZIP metadata, normalized
permissions, and stored compression. It fails on symlinks, stale output,
manifest/hash drift, unsafe archive paths, duplicate skill trees, or recognized
credential material.

| Asset | Contract |
| --- | --- |
| `secuway-vpn-0.4.0.zip` | Standalone upload with one top-level `secuway-vpn/` directory |
| `secuway-vpn-0.4.0.skill` | Byte-identical to the standalone ZIP |
| `secuway-vpn-plugin-0.4.0.zip` | Dual-manifest plugin rooted at `.codex-plugin/`, `.claude-plugin/`, and `skills/` |
| `secuway-vpn-windows-amd64-0.4.0.zip` | amd64 setup bundle with only amd64 PE assets and their required scripts, manifests, and licenses |
| `secuway-vpn-windows-arm64-0.4.0.zip` | ARM64 setup bundle with only ARM64 PE assets and their required scripts, manifests, and licenses |
| `secuway-vpn-0.4.0.spdx.json` | Deterministic SPDX 2.3 SBOM for the project, Go modules, bundled native components, and external runtime dependencies |
| `release-manifest.json` | Version, provenance, canonical-tree digest, size, and SHA-256 for every release artifact |
| `SHA256SUMS` | SHA-256 for all release artifacts and `release-manifest.json` |

Each Windows bundle preserves the layout expected by
`scripts/Setup-Windows.ps1`: the setup and runtime scripts are siblings under
`scripts/`, while the filtered asset manifest and matching PE files live under
`assets/`. Run `Setup-Windows.ps1 -Action Install` from the extracted bundle;
`-Action Uninstall` is destructive to local cached enrollment and should be run
only when that removal is intended.

The root MIT `LICENSE` is injected into standalone uploads and has a
byte-identical copy in the marketplace plugin, so direct plugin-cache installs
and plugin release archives retain the declared license. Bundled third-party
license texts and notices remain under the skill's `licenses/` directory. The
SPDX document records external OpenVPN/OpenSSL runtime dependencies as
dependencies, not redistributed project components.

## Provenance

The skill and Windows payload were imported from
[`mrcha033/skills`](https://github.com/mrcha033/skills) commit
`4e9b843bfcf434be9d76829355f0eee34939bc41`, path
`skills/secuway-vpn`, then normalized for this independent repository and
rebuilt at product/plugin version `0.4.0`. The release manifest records the
current canonical-tree digest, so later normalization is distinguishable from
the imported baseline.

## Security boundary

- Authentication is never bypassed. A first successful server-approved login
  is required before profile reuse.
- Gateway redirects are restricted to the original HTTPS origin.
- Returned PEM blocks, remotes, routes, cipher, and optional directives are
  allow-listed before an OpenVPN configuration is created.
- Windows provider installation verifies the official OpenVPN signatures,
  native architecture, provider hash, protected ACL, and Interactive Service.
- `forget` deletes the locally cached server profile. It does not revoke the
  certificate at the gateway.
- No proprietary Secuway binaries, credentials, profiles, or private keys are
  part of this source tree or its CI artifacts.
- No live tunnel credential, server-issued profile, certificate, private key,
  password, OTP value, or OTP seed belongs in a source, marketplace, package,
  SBOM, release manifest, workflow, or test fixture. Enrollment stays in the
  user's directly visible local terminal and the resulting profile stays in
  the platform-specific protected store.
- Project-produced Windows binaries carry no publisher-signing assertion.
  Their release integrity is established by the recorded SHA-256 values. The
  setup scripts separately verify the publisher signature of the official
  OpenVPN installer and installed OpenVPN components.

See [THIRD_PARTY.md](THIRD_PARTY.md) for pinned upstream components.
