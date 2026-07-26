# Security policy

Report suspected vulnerabilities privately through GitHub's security advisory
form for this repository. Do not include real VPN credentials, OTP values,
cached profiles, private keys, gateway responses, or internal-network details
in a public issue.

Only the latest published release is supported. A cached enrollment profile is
local authentication state, not proof of a live tunnel and not a substitute for
the gateway's first successful server-approved login.

Public CI never receives VPN credentials and never runs a live tunnel on a
self-hosted runner. Live tunnel validation must be performed manually or from a
separate private operations repository after verifying the public release
artifact digest and provenance.
