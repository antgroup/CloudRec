# CloudRec Lite

CloudRec Lite is the local, single-binary CSPM entry point for teams that want
to discover cloud risks quickly without operating the full CloudRec server
stack.

It gives you:

- A CLI scanner and read-only query interface.
- Local SQLite scan history.
- An embedded Web dashboard served from the same binary.
- Alibaba Cloud rule audit, coverage, and validation commands.
- Safer credential storage through the operating system credential store, with a
  local credential-file fallback for headless Linux.

## Install

Download a `cloudrec-lite_<version>_<os>_<arch>.tar.gz` release artifact, verify
its checksum, and unpack it:

```sh
shasum -a 256 -c checksums.txt
tar -xzf cloudrec-lite_<version>_<os>_<arch>.tar.gz
cd cloudrec-lite_<version>_<os>_<arch>
./cloudrec-lite version
```

When running from source during development, use:

```sh
cd lite
go run ./cmd/cloudrec-lite version
```

## Credentials

Store Alibaba Cloud credentials with stdin and the hidden secret prompt. Lite
does not provide an `--access-key-secret` flag because command-line arguments
can be captured by shell history and process inspection.

```sh
printf '%s\n' '<access-key-id>' | ./cloudrec-lite credentials store \
  --provider alicloud \
  --account <account-id> \
  --access-key-id-stdin

./cloudrec-lite credentials status \
  --provider alicloud \
  --account <account-id>
```

After the AccessKey ID is read from stdin, the CLI asks for the AccessKey Secret
with a hidden prompt. In CI, pass both values from masked environment variables
with `--access-key-id-stdin --secret-stdin` instead of putting either value in
the command line.

Credential source resolution defaults to `--credential-source auto`:

- System credential store profile selected by `--credential-profile` or
  `--account`.
- Local credential-file fallback on headless Linux when a Secret Service
  compatible keyring is unavailable.
- Environment variables as a compatibility fallback for one-shot automation.

On Linux fallback, credentials are written under the user configuration
directory as `cloudrec-lite/credentials/alicloud/<profile-hash>.json` with file
mode `0600`. The file uses a random AES-GCM key stored in the same file, so it
avoids plaintext credential exposure but is not a defense against root or the
same OS user reading local files.

Plaintext `.env.local` is supported only as an explicit local development
fallback via `--env-file .env.local`; do not commit or share it.

## First Scan

By default, scan history is stored under your user configuration directory as
`cloudrec-lite/cloudrec-lite.db`. You can still pass `--db <path>` when you want
an explicit database location for testing or automation.

The default Alibaba Cloud rules and validation samples are built into the
binary. Omit `--rules` and `--samples` unless you are testing a custom local
rule pack.

Run diagnostics before a live scan:

```sh
./cloudrec-lite doctor \
  --provider alicloud \
  --account <account-id>
```

Run a focused Alibaba Cloud scan:

```sh
./cloudrec-lite scan \
  --provider alicloud \
  --account <account-id> \
  --dry-run=false
```

Use `--resource-types`, `--region` or `--regions`, `--collector-timeout`, and
`--collector-concurrency` to keep large accounts predictable. For high-cardinality
RAM accounts, a timeout such as `--collector-timeout 180s` is usually easier to
operate than one very broad default scan.

For the minimum RAM policy starting point and Alibaba Cloud resource-region
exceptions, see the source repository docs:

- https://github.com/antgroup/CloudRec/blob/main/docs/alicloud-minimum-ram-policy.md
- https://github.com/antgroup/CloudRec/blob/main/docs/alicloud-resource-region-matrix.md

## Web Dashboard

Serve the local dashboard from the scan DB:

```sh
./cloudrec-lite serve \
  --provider alicloud \
  --addr 127.0.0.1:8787
```

Open `http://127.0.0.1:8787/`.

The dashboard is read-only in Lite v1. It shows overview posture, risks, assets,
asset topology, scan quality, rules, and local settings without requiring a
remote server or login.

## CLI Queries

The common Web read models are also available from CLI:

```sh
./cloudrec-lite dashboard --format table
./cloudrec-lite risks list --status open --limit 20
./cloudrec-lite risks show <finding-id> --format json
./cloudrec-lite assets list --resource-type OSS --limit 20
./cloudrec-lite assets show <asset-id> --format json
./cloudrec-lite rules list --provider alicloud --severity high --format table
./cloudrec-lite rules show alicloud.oss_202501081111_563734 --provider alicloud --format json
./cloudrec-lite scans list --limit 20
./cloudrec-lite scans quality --provider alicloud --format table
./cloudrec-lite facets --format table
```

List commands support pagination with `--limit` and `--offset`; most list
commands also support `--format table|json|csv`. Topology and risk-path
investigation intentionally remain Web-only because they are visual workflows.

## Rule Quality

Use rule quality commands before changing rules or trusting a new rule pack:

```sh
./cloudrec-lite rules audit \
  --provider alicloud \
  --format table

./cloudrec-lite rules coverage \
  --provider alicloud \
  --format table

./cloudrec-lite rules validate \
  --provider alicloud \
  --format table
```

From the source tree, you can still pass `--rules ./rules/alicloud` and
`--samples ./samples/alicloud` when validating an edited local rule pack.

The current Alibaba Cloud Lite rule pack is release-gated at 84 active rules,
35 resource types, 84 official reviews, 0 missing data references, and 0 missing
sample references in the source-tree quality gate.

## Remediation Export

Generate local repair notes after a scan:

```sh
./cloudrec-lite export remediation \
  --status open \
  --format markdown \
  --output remediation.md
```

Exports redact sensitive evidence keys and do not print AK/SK values.
