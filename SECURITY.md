# Security Policy

## Reporting Vulnerabilities

Please report security vulnerabilities privately through GitHub Security
Advisories for this repository. Do not open a public issue with exploit details,
cloud account identifiers, AccessKey material, database dumps, or screenshots
that expose sensitive resources.

If you accidentally share a real cloud credential in an issue, pull request,
chat, log, or local test artifact, rotate or delete that credential immediately.
Treat any credential that has left your own secret store as compromised.

## Credential Handling

CloudRec Lite should not require credentials to be saved in plaintext files.
The recommended local flow is:

```sh
cloudrec-lite credentials store --provider alicloud --account <account-id> --access-key-id-stdin
```

Then paste the AccessKey ID, press Enter, and enter the AccessKey secret through
the hidden prompt. The credential is stored in the operating system credential
store, such as macOS Keychain, Windows Credential Manager, or a Linux Secret
Service compatible keyring.

On headless Linux servers where Secret Service is unavailable, CloudRec Lite
falls back to a local encrypted credential file under the user's config
directory. The randomly generated data key is stored in the same file by design
for low-friction local use. This protects against plaintext-at-rest and
accidental file sharing, but it does not protect against same-user or root
filesystem access.

Environment variables are still supported for one-shot CI or development runs:

```sh
ALIBABA_CLOUD_ACCESS_KEY_ID=... ALIBABA_CLOUD_ACCESS_KEY_SECRET=... cloudrec-lite scan --credential-source env ...
```

`.env.local` remains a local-only compatibility fallback, but it should never be
committed, shared, or used for published examples.

## Scope

CloudRec Lite is a local read-only CSPM scanner and dashboard. It should not
print AK/SK values, security tokens, raw credential files, or secret-bearing
evidence fields in CLI output, Web UI pages, exported remediation reports, or
doctor diagnostics.
