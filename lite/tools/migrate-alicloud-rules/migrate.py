#!/usr/bin/env python3
"""Migrate legacy CloudRec ALI_CLOUD rules into CloudRec Lite rule packs."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any


REQUIRED_RULE_FILES = ("metadata.json", "policy.rego", "input.json", "relation.json")

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}

SERVICE_ALIASES = {
    "ack_cluster": "ack",
    "analyticdb_postgresql": "analyticdb",
    "cloudfw_config": "cloudfw",
    "eci_containergroup": "eci",
    "eci_container_group": "eci",
    "ecs_image": "ecs",
    "ens_instance": "ens",
    "ens_natgateway": "ens",
    "ens_nat_gateway": "ens",
    "ram_role": "ram",
    "ram_user": "ram",
}

PACKAGE_RE = re.compile(
    r"(?m)^\s*package\s+([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*$"
)
DATA_REF_RE = re.compile(r"\bdata\.([A-Za-z_][A-Za-z0-9_]*)")


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[3]


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_script()
    parser = argparse.ArgumentParser(
        description="Migrate rules/ALI_CLOUD into lite/rules/alicloud."
    )
    parser.add_argument("--repo-root", type=Path, default=repo_root)
    parser.add_argument("--source", type=Path, default=Path("rules/ALI_CLOUD"))
    parser.add_argument("--data-source", type=Path, default=Path("rules/data"))
    parser.add_argument("--target", type=Path, default=Path("lite/rules/alicloud"))
    parser.add_argument("--data-target", type=Path, default=Path("lite/rules/data"))
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("lite/tools/migrate-alicloud-rules/manifest.json"),
        help="Write a machine-readable migration manifest.",
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def resolve_path(repo_root: Path, path: Path) -> Path:
    if path.is_absolute():
        return path
    return repo_root / path


def read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc}") from exc


def write_json(path: Path, value: Any, dry_run: bool) -> None:
    content = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    if dry_run:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def copy_file(source: Path, target: Path, dry_run: bool) -> None:
    if dry_run:
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def normalize_identifier(value: Any) -> str:
    text = str(value or "").strip()
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    text = re.sub(r"[^A-Za-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_").lower()
    return text


def severity_from_level(level: Any) -> str:
    normalized = str(level or "").strip().lower()
    return SEVERITY_MAP.get(normalized, "info")


def service_from_asset_type(asset_type: str) -> str:
    if asset_type in SERVICE_ALIASES:
        return SERVICE_ALIASES[asset_type]
    if "_" in asset_type:
        return asset_type.split("_", 1)[0]
    return asset_type or "unknown"


def lite_rule_id(code: str) -> str:
    normalized = normalize_identifier(code)
    if normalized.startswith("ali_cloud_"):
        normalized = normalized[len("ali_cloud_") :]
    return f"alicloud.{normalized or 'unknown'}"


def detect_package(policy: str, policy_path: Path) -> str:
    match = PACKAGE_RE.search(policy)
    if not match:
        raise ValueError(f"missing Rego package in {policy_path}")
    return match.group(1)


def has_entrypoint(policy: str, name: str) -> bool:
    pattern = re.compile(
        rf"(?m)^\s*{re.escape(name)}(?:\s+contains|\s+if|\s*:=|\s*=|\s*\[|\s*\{{)"
    )
    return bool(pattern.search(policy))


def detect_entrypoint(policy: str) -> str:
    for candidate in ("messages", "findings", "risk"):
        if has_entrypoint(policy, candidate):
            return candidate
    return "risk"


def referenced_data_documents(policy: str) -> set[str]:
    return set(DATA_REF_RE.findall(policy))


def build_metadata(source_dir: Path, legacy: dict[str, Any], policy: str) -> dict[str, Any]:
    code = str(legacy.get("code") or source_dir.name)
    resource_type = legacy.get("resourceType") or source_dir.name
    asset_type = normalize_identifier(resource_type) or normalize_identifier(source_dir.name)
    service = service_from_asset_type(asset_type)
    package = detect_package(policy, source_dir / "policy.rego")
    entrypoint = detect_entrypoint(policy)
    categories = legacy.get("categoryList")
    if not isinstance(categories, list):
        categories = []

    metadata: dict[str, Any] = {
        "id": lite_rule_id(code),
        "name": legacy.get("name") or code,
        "version": "legacy",
        "description": legacy.get("description") or "",
        "severity": severity_from_level(legacy.get("level")),
        "provider": "alicloud",
        "service": service,
        "asset_type": asset_type,
        "categories": categories,
        "tags": ["legacy", "alicloud", service],
        "query": f"data.{package}.{entrypoint}",
        "entrypoint": entrypoint,
        "legacy": legacy,
    }
    return metadata


def validate_rule_dir(rule_dir: Path) -> None:
    missing = [name for name in REQUIRED_RULE_FILES if not (rule_dir / name).is_file()]
    if missing:
        raise ValueError(f"{rule_dir} missing required file(s): {', '.join(missing)}")


def migrate_rules(source_root: Path, target_root: Path, dry_run: bool) -> tuple[list[dict[str, Any]], set[str]]:
    if not source_root.is_dir():
        raise ValueError(f"source rule directory does not exist: {source_root}")

    migrated: list[dict[str, Any]] = []
    data_refs: set[str] = set()

    for source_dir in sorted(path for path in source_root.iterdir() if path.is_dir()):
        validate_rule_dir(source_dir)
        legacy_metadata = read_json(source_dir / "metadata.json")
        if not isinstance(legacy_metadata, dict):
            raise ValueError(f"metadata must be an object: {source_dir / 'metadata.json'}")

        policy = (source_dir / "policy.rego").read_text(encoding="utf-8")
        metadata = build_metadata(source_dir, legacy_metadata, policy)
        data_refs.update(referenced_data_documents(policy))

        target_dir = target_root / source_dir.name
        write_json(target_dir / "metadata.json", metadata, dry_run)
        copy_file(source_dir / "policy.rego", target_dir / "policy.rego", dry_run)
        copy_file(source_dir / "input.json", target_dir / "input.json", dry_run)
        copy_file(source_dir / "relation.json", target_dir / "relation.json", dry_run)

        migrated.append(
            {
                "id": metadata["id"],
                "name": metadata["name"],
                "provider": metadata["provider"],
                "service": metadata["service"],
                "asset_type": metadata["asset_type"],
                "severity": metadata["severity"],
                "query": metadata["query"],
                "source_dir": str(source_dir),
                "target_dir": str(target_dir),
                "files": [
                    str(target_dir / "metadata.json"),
                    str(target_dir / "policy.rego"),
                    str(target_dir / "input.json"),
                    str(target_dir / "relation.json"),
                ],
            }
        )

    return migrated, data_refs


def copy_data_documents(data_source: Path, data_target: Path, data_refs: set[str], dry_run: bool) -> list[str]:
    copied: list[str] = []
    for name in sorted(data_refs):
        source = data_source / f"{name}.json"
        if not source.is_file():
            raise ValueError(f"policy references data.{name}, but {source} does not exist")
        read_json(source)
        target = data_target / source.name
        copy_file(source, target, dry_run)
        copied.append(str(target))
    return copied


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    source_root = resolve_path(repo_root, args.source)
    data_source = resolve_path(repo_root, args.data_source)
    target_root = resolve_path(repo_root, args.target)
    data_target = resolve_path(repo_root, args.data_target)
    manifest_path = resolve_path(repo_root, args.manifest)

    try:
        migrated, data_refs = migrate_rules(source_root, target_root, args.dry_run)
        data_files = copy_data_documents(data_source, data_target, data_refs, args.dry_run)

        manifest = {
            "rules_migrated": len(migrated),
            "rule_root": str(target_root),
            "data_files_copied": len(data_files),
            "data_root": str(data_target),
            "rules": migrated,
            "data_files": data_files,
        }
        write_json(manifest_path, manifest, args.dry_run)

        print(f"Migrated rules: {len(migrated)}")
        print(f"Rule output: {target_root}")
        print(f"Copied data files: {len(data_files)}")
        print(f"Data output: {data_target}")
        print(f"Manifest: {manifest_path}")
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
