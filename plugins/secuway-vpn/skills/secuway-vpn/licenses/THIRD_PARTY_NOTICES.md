# Secuway VPN third-party notices

This directory is distributed with every `secuway-vpn` skill bundle. It
contains the unmodified upstream license, patent, credit, and runtime-notice
files required for the prebuilt Windows assets under `../assets/`.

`manifest.json` is the machine-readable source of truth for exact versions,
source revisions, upstream URLs, file hashes, and binary scope.

## What is embedded in each binary

| Distributed asset | Statically included third-party code |
| --- | --- |
| `windows-amd64/secuway.exe` | Go 1.25.4 standard library, `golang.org/x/sys` v0.47.0, and `golang.org/x/term` v0.45.0 |
| `windows-arm64/secuway.exe` | Go 1.25.4 standard library, `golang.org/x/sys` v0.47.0, and `golang.org/x/term` v0.45.0 |
| `windows-amd64/lea.dll` | Crypto++ 8.9.0, GCC 12.2.0 `libstdc++`/`libgcc` runtime code, and MinGW-w64 10.0.0 runtime code |
| `windows-amd64/provider_smoke.exe` | GCC 12.2.0 support code as needed and MinGW-w64 10.0.0 runtime code |
| `windows-arm64/lea.dll` | Crypto++ 8.9.0 plus the Microsoft Visual C++ v143 static CRT and C++ standard library selected by `/MT` (`libcmt.lib`, `libvcruntime.lib`, `libucrt.lib`, and `libcpmt.lib`) |
| `windows-arm64/provider_smoke.exe` | Microsoft Visual C++ v143 static CRT selected by `/MT` (`libcmt.lib`, `libvcruntime.lib`, and `libucrt.lib`) |

The AMD64 provider was produced by the pinned Debian 12 builder using the
Debian `gcc-mingw-w64` 12.2.0 package family
(`12.2.0-14+deb12u1+25.2+b1`) and MinGW-w64 `10.0.0-3`. The ARM64 assets
were produced natively on GitHub's `windows-11-arm` image
`20260719.114.1` using Visual Studio 2022 Enterprise `17.14.36`,
VCTools `14.44.35207`, MSVC `19.44.35228.0`, linker `14.44`, and Windows
SDK `10.0.26100.0`. Their Microsoft runtimes are statically linked with
`/MT`; they do not embed LLVM or MinGW-w64 runtime code and do not require
Visual C++ runtime DLLs beside the assets.

## Bundled upstream texts

- `go/LICENSE` and `go/PATENTS`: Go toolchain and standard library.
- `golang.org-x-sys/LICENSE` and `golang.org-x-sys/PATENTS`:
  `golang.org/x/sys`.
- `golang.org-x-term/LICENSE` and `golang.org-x-term/PATENTS`:
  `golang.org/x/term`.
- `cryptopp/LICENSE.txt`: Crypto++ compilation license, Boost Software
  License 1.0, public-domain declaration, and CRYPTOGAMS notice.
- `gcc/COPYING3` and `gcc/COPYING.RUNTIME`: GNU GPL version 3 and the GCC
  Runtime Library Exception version 3.1 for statically linked GCC runtime
  code.
- `mingw-w64/amd64-COPYING.MinGW-w64-runtime.txt`: the exact upstream
  runtime notice corresponding to the AMD64 provider build.
- `microsoft/Visual-Studio-2022-Enterprise-Professional-License-EN.docx`:
  the unmodified Microsoft Visual Studio 2022 Enterprise/Professional
  Software License Terms obtained from Microsoft's Visual Studio License
  Directory. Microsoft documents `/MT` as statically linking the CRT and
  publishes the applicable Visual Studio 2022 distributable-code list
  separately; both official documentation URLs are pinned in
  `manifest.json`.

The pinned open-source trees do not publish a standalone top-level `NOTICE`
file for these components. Where upstream publishes `PATENTS` or a
dedicated MinGW runtime notice, that file is included here without
modification. No Microsoft license text was transcribed or rewritten.

## Dynamically supplied software

OpenVPN Community `2.7.5-I001` and its OpenSSL `3.6.3` `libcrypto` are not
redistributed in this skill. The setup script downloads and verifies the
official OpenVPN installer, and `lea.dll` dynamically resolves the
architecture-specific `libcrypto` installed by that package. Their source
and installer identities remain recorded in `../assets/manifest.json` and
the native build manifests.
