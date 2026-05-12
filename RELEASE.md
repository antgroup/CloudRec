# CloudRec Lite Release Checklist

This checklist is the source of truth for publishing a CloudRec Lite release.
Run it from a clean working tree or an explicit release branch.

## 1. Prepare

- Confirm `LICENSE`, `SECURITY.md`, `lite/README.md`, and the Alibaba Cloud rule
  pack are included in the intended release scope.
- Confirm no real account DB, `.env.local`, release tarball, checksum file, or
  local remediation export is staged.
- Confirm the release tag format is `lite-vX.Y.Z`; the binary version inside the
  archive is `vX.Y.Z`.

## 2. Local Quality Gate

Run from `lite/`:

```sh
go test -p 1 ./...
go test ./tools -run TestBuildReleasePackagesLicenseAndSecurityFiles -count=1
node --check internal/server/web/app.js
go test ./internal/rule -run TestAlicloudReleaseQualityGate -count=1
```

`-p 1` keeps the release gate deterministic on smaller laptops and CI runners
because the CLI package links a broad provider dependency graph. It does not
skip any package or test.

Run rule quality checks from `lite/`:

```sh
go run ./cmd/cloudrec-lite rules audit \
  --rules ./rules/alicloud \
  --provider alicloud \
  --review-ledger ./rules/alicloud/review-ledger.json \
  --format json

go run ./cmd/cloudrec-lite rules coverage \
  --rules ./rules/alicloud \
  --provider alicloud \
  --samples ./samples/alicloud \
  --review-ledger ./rules/alicloud/review-ledger.json \
  --format json

go run ./cmd/cloudrec-lite rules validate \
  --rules ./rules/alicloud \
  --provider alicloud \
  --samples ./samples/alicloud \
  --format json
```

Expected release gate for the current Alibaba Cloud Lite scope:

- `audit`: 84 `official_reviewed`, 0 `needs_logic_change`, 0
  `missing_remediation`.
- `coverage`: 84 rules, 35 resource types, 0 `missing_data_refs`, 35 verified
  resources.
- `validate`: 84 `real_field_verified`, 108 passing examples, 0 missing fixture
  refs, 0 missing sample refs.

## 3. Secret Scan

Run from the repository root:

```sh
GOTOOLCHAIN=auto GOPROXY=https://proxy.golang.org,direct \
  go run github.com/zricethezav/gitleaks/v8@latest dir . \
  --config .gitleaks.toml \
  --redact \
  --no-banner \
  --no-color

GOTOOLCHAIN=auto GOPROXY=https://proxy.golang.org,direct \
  go run github.com/zricethezav/gitleaks/v8@latest git . \
  --config .gitleaks.toml \
  --redact \
  --no-banner \
  --no-color
```

Both commands must report `no leaks found`. If a real credential was ever pasted
into chat, issue trackers, logs, or local plaintext files, rotate it even when
the repository scan is clean.

## 4. Build Release Artifacts

Run from `lite/`:

```sh
VERSION=vX.Y.Z DIST=/tmp/cloudrec-lite-dist ./tools/build-release.sh
cd /tmp/cloudrec-lite-dist
shasum -a 256 -c checksums.txt
tar -tzf cloudrec-lite_vX.Y.Z_linux_amd64.tar.gz | grep -E '/(LICENSE|README.md|SECURITY.md)$|/rules/$|/cloudrec-lite$'
```

The archive must include `LICENSE`, `README.md`, `SECURITY.md`, `rules/`, and
the platform binary.

## 5. Linux Binary Smoke

Before creating the GitHub Release, copy the Linux archive and `checksums.txt`
to a Linux host and run a non-secret smoke test:

```sh
mkdir -p /tmp/cloudrec-lite-smoke
cp cloudrec-lite_vX.Y.Z_linux_amd64.tar.gz checksums.txt /tmp/cloudrec-lite-smoke/
cd /tmp/cloudrec-lite-smoke
sha256sum -c checksums.txt
tar -xzf cloudrec-lite_vX.Y.Z_linux_amd64.tar.gz
cd cloudrec-lite_vX.Y.Z_linux_amd64
./cloudrec-lite version
./cloudrec-lite doctor --provider mock --rules ./rules/alicloud --db /tmp/cloudrec-lite-linux-smoke.db --env-file ""
./cloudrec-lite scan --provider mock --account linux-smoke --rules ./rules --db /tmp/cloudrec-lite-linux-smoke.db --dry-run=false
./cloudrec-lite dashboard --db /tmp/cloudrec-lite-linux-smoke.db --format json
./cloudrec-lite rules audit --rules ./rules/alicloud --provider alicloud --review-ledger ./rules/alicloud/review-ledger.json --format json
```

Do not copy real credentials, `.env*` files, or real account SQLite databases to
the Linux smoke host.

Record the Linux host class, date, artifact checksum, and command result in the
release issue or release PR. Do not publish the first GitHub Release until this
Linux smoke completes on a real host.

## 6. Publish

1. Push the release branch and confirm GitHub CI plus Secret Scan are green.
2. Create and push `lite-vX.Y.Z`.
3. Confirm the release workflow uploads archives, `checksums.txt`, and artifact
   provenance attestation.
4. The release workflow must rerun Go tests, Web syntax check, rule quality
   gates, secret scan, and checksum/package-content verification before it
   publishes a tag-triggered GitHub Release.
5. Download one archive from GitHub Releases and repeat the checksum and
   `./cloudrec-lite version` smoke locally.

## 7. Post-Release

- Verify `docs/cloudrec-lite-v0.1.0-release-notes.md` matches the published
  version.
- Keep internal review history in the local maintainer repository, not in the
  public release tree. User-facing docs should stay focused on install,
  credentials, scanning, Web, CLI queries, and rule quality.
