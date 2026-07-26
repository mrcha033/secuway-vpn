# Release administration

Before pushing the first `v*` tag:

1. Make the repository public and enable immutable releases.
2. Protect `main` with the package and native Windows checks.
3. Create an environment named `release` with a required reviewer.
4. Set the environment variable `SECUWAY_RELEASE_POLICY` to `immutable-v1`
   only after immutable releases and the reviewer gate are active.
5. Enable private vulnerability reporting and Dependabot security updates.

The release workflow accepts only stable `vMAJOR.MINOR.PATCH` tags. It reruns
package, Windows CLI, x64 provider/install, and ARM64 provider validation for
the exact tagged commit. After approval it builds the deterministic dist,
generates provenance and SBOM attestations, uploads every asset to a draft,
verifies GitHub's asset digests, and publishes the draft.

Never add credentials, profiles, private keys, a campus-reachable self-hosted
runner, or a live tunnel workflow to this public repository.
