# CloudRec Lite v0.1.0 Release Notes Draft

CloudRec Lite is a local, single-binary CSPM scanner and dashboard for teams
that want to quickly inspect cloud asset posture without deploying the full
CloudRec platform.

## Highlights

- Alibaba Cloud Lite scanner with native/compatibility collector coverage for
  core assets such as Account, RAM, OSS, ECS, Security Group, SLB/ALB/NLB, RDS,
  Redis, and MongoDB.
- Local SQLite scan history and a zero-build Web dashboard served by the CLI.
- Rule quality commands for audit, coverage, validation, and remediation export.
- Sanitized Alibaba Cloud sample pack for stable field-contract validation
  without using real account data.
- Asset topology views for public traffic exposure and AK permission paths.
- OS credential store support through `cloudrec-lite credentials
  store/status/delete`; plaintext `.env.local` is fallback-only.

## Quickstart

```sh
cloudrec-lite version
printf '%s\n' '<access-key-id>' | cloudrec-lite credentials store --provider alicloud --account <account-id> --access-key-id-stdin
cloudrec-lite doctor --provider alicloud --account <account-id> --rules ./rules/alicloud
cloudrec-lite scan --provider alicloud --account <account-id> --rules ./rules/alicloud --dry-run=false
cloudrec-lite serve --rules ./rules/alicloud --provider alicloud
```

The default SQLite database is stored under the user's configuration directory
as `cloudrec-lite/cloudrec-lite.db`; pass `--db <path>` for temporary or
automation-specific databases.

## Known Limitations

- The first release is local and read-only. It does not provide account CRUD,
  scheduled scans, team access control, risk ignore workflows, or rule editing.
- Live scans depend on Alibaba Cloud API permissions and product availability.
  Permission, throttling, unsupported-region, disabled-product, and timeout
  failures are recorded as partial collection failures instead of failing the
  whole scan when possible.
- Real account credentials should be rotated if they were ever pasted into chat,
  issue trackers, logs, or local plaintext files.

## Verification Before Tagging

Run from `lite/`:

```sh
go test -p 1 ./...
node --check internal/server/web/app.js
go run ./cmd/cloudrec-lite rules audit --rules ./rules/alicloud --provider alicloud --review-ledger ./rules/alicloud/review-ledger.json --format json
go run ./cmd/cloudrec-lite rules coverage --rules ./rules/alicloud --provider alicloud --samples ./samples/alicloud --review-ledger ./rules/alicloud/review-ledger.json --format json
go run ./cmd/cloudrec-lite rules validate --rules ./rules/alicloud --provider alicloud --samples ./samples/alicloud --format json
go test ./internal/rule -run TestAlicloudReleaseQualityGate
DIST=/tmp/cloudrec-lite-dist ./tools/build-release.sh
```
