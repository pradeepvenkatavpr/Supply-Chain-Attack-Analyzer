from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


@dataclass
class SupplyChainFinding:
    title: str
    severity: str
    category: str
    description: str
    package: str | None = None
    rule_id: str | None = None
    source_file: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SupplyChainAnalyzer:
    def __init__(
        self,
        config: dict[str, Any] | None = None,
        policies: dict[str, Any] | None = None,
        rules: dict[str, Any] | None = None,
    ) -> None:
        self.config = config or {}
        self.policies = policies or {}
        self.rules = rules or {}
        self.findings: list[SupplyChainFinding] = []
        self.approved_hosts = set(
            self.policies.get("provenance_policy", {}).get("approved_hosts", [])
        )
        self.accepted_hashes = set(
            self.policies.get("integrity_policy", {}).get(
                "accepted_hash_algorithms",
                ["sha256", "sha384", "sha512"],
            )
        )
        self.denied_licenses = set(
            self.policies.get("license_policy", {}).get("denied_licenses", [])
        )
        self.review_licenses = set(
            self.policies.get("license_policy", {}).get("review_licenses", [])
        )

    def analyze(self, dependencies: list[Any]) -> dict[str, Any]:
        return self.analyze_dependencies(dependencies)

    def inspect(self, dependencies: list[Any]) -> dict[str, Any]:
        return self.analyze_dependencies(dependencies)

    def analyze_dependencies(self, dependencies: list[Any]) -> dict[str, Any]:
        findings: list[SupplyChainFinding] = []
        for raw in dependencies:
            item = self.normalize_dependency(raw)
            if item is None:
                continue
            findings.extend(self.inspect_dependency(item))
        unique = self.deduplicate(findings)
        self.findings.extend(unique)
        return {
            "findings": [item.to_dict() for item in unique],
            "finding_count": len(unique),
            "summary": self.summarize(unique),
        }

    def normalize_dependency(self, raw: Any) -> dict[str, Any] | None:
        if hasattr(raw, "to_dict"):
            raw = raw.to_dict()
        if not isinstance(raw, dict):
            return None
        name = raw.get("name")
        if not name:
            return None
        return {
            "name": str(name),
            "version": str(raw["version"]) if raw.get("version") is not None else None,
            "ecosystem": str(raw.get("ecosystem", "unknown")).lower(),
            "source_file": raw.get("source_file"),
            "source_url": raw.get("source_url"),
            "vcs": bool(raw.get("vcs", False)),
            "commit": raw.get("commit"),
            "hashes": list(raw.get("hashes", [])),
            "license": raw.get("license"),
            "metadata": raw.get("metadata", {}),
            "direct": bool(raw.get("direct", True)),
        }

    def inspect_dependency(self, dependency: dict[str, Any]) -> list[SupplyChainFinding]:
        findings: list[SupplyChainFinding] = []
        findings.extend(self.check_source(dependency))
        findings.extend(self.check_vcs_provenance(dependency))
        findings.extend(self.check_hashes(dependency))
        findings.extend(self.check_license(dependency))
        findings.extend(self.check_version(dependency))
        findings.extend(self.check_metadata(dependency))
        return findings

    def check_source(self, dependency: dict[str, Any]) -> list[SupplyChainFinding]:
        policy = self.policies.get("provenance_policy", {})
        source = dependency.get("source_url")
        if not source:
            if policy.get("require_source_repository", False):
                return [
                    self.finding(
                        title="Dependency source metadata is missing",
                        severity="medium",
                        category="provenance",
                        description="The dependency record does not identify its source URL.",
                        dependency=dependency,
                        rule_id="SC-005",
                        recommendation="Verify the package source using an authoritative lockfile or registry record.",
                    )
                ]
            return []
        parsed = urlparse(str(source))
        if parsed.scheme in {"http", "git+http", "git"}:
            return [
                self.finding(
                    title="Dependency source uses an insecure transport",
                    severity="high",
                    category="provenance",
                    description="The source URL uses a transport without HTTPS protection.",
                    dependency=dependency,
                    rule_id="SC-005",
                    evidence={"source_url": source, "scheme": parsed.scheme},
                    recommendation="Use a trusted HTTPS registry or authenticated secure source.",
                )
            ]
        if parsed.scheme in {"https", "ssh", "git+https", "git+ssh"}:
            host = (parsed.hostname or "").lower()
            if self.approved_hosts and host and host not in self.approved_hosts:
                return [
                    self.finding(
                        title="Dependency source host is not approved",
                        severity="high",
                        category="provenance",
                        description="The source host is not present in the configured approved-host list.",
                        dependency=dependency,
                        rule_id="SC-005",
                        evidence={"host": host},
                        recommendation="Validate the source and update the approved-host policy through review.",
                    )
                ]
        return []

    def check_vcs_provenance(
        self,
        dependency: dict[str, Any],
    ) -> list[SupplyChainFinding]:
        policy = self.policies.get("dependency_policy", {})
        if not dependency.get("vcs"):
            return []
        commit = dependency.get("commit")
        if policy.get("reject_vcs_dependencies_without_commit", True) and not commit:
            return [
                self.finding(
                    title="VCS dependency is not tied to an immutable commit",
                    severity="high",
                    category="provenance",
                    description="The VCS dependency has no detected commit identifier.",
                    dependency=dependency,
                    rule_id="SC-009",
                    evidence={"source_url": dependency.get("source_url")},
                    recommendation="Pin the dependency to a reviewed immutable commit.",
                )
            ]
        if commit and not re.fullmatch(r"[0-9a-fA-F]{7,64}", str(commit)):
            return [
                self.finding(
                    title="VCS commit reference is malformed",
                    severity="medium",
                    category="provenance",
                    description="The supplied commit reference does not match the expected hexadecimal format.",
                    dependency=dependency,
                    evidence={"commit": commit},
                    recommendation="Verify the commit reference against the authoritative repository.",
                )
            ]
        return []

    def check_hashes(self, dependency: dict[str, Any]) -> list[SupplyChainFinding]:
        policy = self.policies.get("integrity_policy", {})
        hashes = dependency.get("hashes", [])
        if not hashes:
            if policy.get("require_hashes_for_release_artifacts", False):
                return [
                    self.finding(
                        title="Dependency integrity hash is missing",
                        severity="high",
                        category="artifact_integrity",
                        description="No integrity hash was supplied for the dependency record.",
                        dependency=dependency,
                        rule_id="SC-004",
                        recommendation="Use a lockfile or artifact record with a verified checksum.",
                    )
                ]
            return []
        findings = []
        for value in hashes:
            algorithm, digest = self.parse_hash(str(value))
            if not algorithm or not digest:
                findings.append(
                    self.finding(
                        title="Dependency hash format is invalid",
                        severity="medium",
                        category="artifact_integrity",
                        description="A supplied hash could not be parsed into an algorithm and digest.",
                        dependency=dependency,
                        rule_id="SC-004",
                        evidence={"hash": self.redact_hash(str(value))},
                        recommendation="Regenerate the lockfile or checksum metadata from a trusted source.",
                    )
                )
                continue
            if algorithm not in self.accepted_hashes:
                findings.append(
                    self.finding(
                        title="Dependency hash algorithm is not accepted",
                        severity="medium",
                        category="artifact_integrity",
                        description="The configured integrity policy does not accept this hash algorithm.",
                        dependency=dependency,
                        rule_id="SC-004",
                        evidence={"algorithm": algorithm},
                        recommendation="Use a policy-approved cryptographic hash algorithm.",
                    )
                )
        return findings

    def parse_hash(self, value: str) -> tuple[str | None, str | None]:
        if ":" in value:
            algorithm, digest = value.split(":", 1)
            algorithm = algorithm.lower()
            if algorithm in {"sha256", "sha384", "sha512", "sha1", "md5"}:
                return algorithm, digest
            return None, None
        if re.fullmatch(r"[0-9a-fA-F]{64}", value):
            return "sha256", value
        if re.fullmatch(r"[0-9a-fA-F]{96}", value):
            return "sha384", value
        if re.fullmatch(r"[0-9a-fA-F]{128}", value):
            return "sha512", value
        return None, None

    def redact_hash(self, value: str) -> str:
        if len(value) <= 16:
            return value
        return value[:8] + "..." + value[-4:]

    def check_license(self, dependency: dict[str, Any]) -> list[SupplyChainFinding]:
        policy = self.policies.get("license_policy", {})
        license_name = dependency.get("license")
        if not license_name:
            if policy.get("require_license_metadata", False):
                return [
                    self.finding(
                        title="License metadata is missing",
                        severity="medium",
                        category="licensing",
                        description="The dependency record does not include license metadata.",
                        dependency=dependency,
                        rule_id="SC-006",
                        recommendation="Verify licensing from trusted package metadata and record the result.",
                    )
                ]
            return []
        normalized = str(license_name).strip()
        if normalized in self.denied_licenses:
            return [
                self.finding(
                    title="Dependency license is denied by policy",
                    severity="high",
                    category="licensing",
                    description="The dependency license appears in the configured denied-license list.",
                    dependency=dependency,
                    rule_id="SC-006",
                    evidence={"license": normalized},
                    recommendation="Obtain legal review and choose an approved alternative where necessary.",
                )
            ]
        if normalized in self.review_licenses:
            return [
                self.finding(
                    title="Dependency license requires review",
                    severity="medium",
                    category="licensing",
                    description="The dependency license is configured for review.",
                    dependency=dependency,
                    rule_id="SC-006",
                    evidence={"license": normalized},
                    recommendation="Review obligations with the organization's software licensing process.",
                )
            ]
        return []

    def check_version(self, dependency: dict[str, Any]) -> list[SupplyChainFinding]:
        version = dependency.get("version")
        if not version:
            return [
                self.finding(
                    title="Resolved dependency version is missing",
                    severity="medium",
                    category="reproducibility",
                    description="The dependency record does not identify a resolved version.",
                    dependency=dependency,
                    rule_id="SC-002",
                    recommendation="Resolve the dependency and preserve its exact version in the lockfile.",
                )
            ]
        value = str(version).strip()
        if value in {"latest", "*", "master", "main", "HEAD"}:
            return [
                self.finding(
                    title="Dependency uses a mutable version reference",
                    severity="high",
                    category="reproducibility",
                    description="The version value may resolve to different content over time.",
                    dependency=dependency,
                    rule_id="SC-002",
                    evidence={"version": value},
                    recommendation="Pin a released version or immutable source revision.",
                )
            ]
        return []

    def check_metadata(self, dependency: dict[str, Any]) -> list[SupplyChainFinding]:
        findings = []
        metadata = dependency.get("metadata", {})
        if not isinstance(metadata, dict):
            return [
                self.finding(
                    title="Dependency metadata has an invalid shape",
                    severity="low",
                    category="input_quality",
                    description="Expected metadata to be a mapping.",
                    dependency=dependency,
                    evidence={"metadata_type": type(metadata).__name__},
                )
            ]
        if metadata.get("deprecated") is True:
            findings.append(
                self.finding(
                    title="Dependency is marked deprecated",
                    severity="medium",
                    category="maintenance",
                    description="Available package metadata marks this dependency as deprecated.",
                    dependency=dependency,
                    evidence={"deprecated": True},
                    recommendation="Review maintenance status and supported alternatives.",
                )
            )
        if metadata.get("yanked") is True:
            findings.append(
                self.finding(
                    title="Dependency release is yanked",
                    severity="high",
                    category="package_integrity",
                    description="Package metadata indicates that this release has been yanked.",
                    dependency=dependency,
                    evidence={"yanked": True},
                    recommendation="Investigate the reason for yanking and select a trusted release.",
                )
            )
        return findings

    def finding(
        self,
        title: str,
        severity: str,
        category: str,
        description: str,
        dependency: dict[str, Any],
        rule_id: str | None = None,
        evidence: dict[str, Any] | None = None,
        recommendation: str | None = None,
    ) -> SupplyChainFinding:
        return SupplyChainFinding(
            title=title,
            severity=severity,
            category=category,
            description=description,
            package=dependency.get("name"),
            rule_id=rule_id,
            source_file=dependency.get("source_file"),
            evidence={
                "version": dependency.get("version"),
                "ecosystem": dependency.get("ecosystem"),
                **(evidence or {}),
            },
            recommendation=recommendation,
        )

    def analyze_file(self, path: str | Path) -> dict[str, Any]:
        source = Path(path)
        if not source.exists() or not source.is_file():
            raise FileNotFoundError(str(source))
        content = source.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        return {
            "path": str(source.resolve()),
            "size_bytes": len(content),
            "sha256": digest,
            "findings": [],
        }

    def scan_manifest_text(self, content: str, source_name: str = "manifest") -> dict[str, Any]:
        findings = []
        patterns = [
            ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
            ("token_assignment", r"(?i)\b(?:token|secret|password|api_key)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{12,}"),
        ]
        for label, pattern in patterns:
            for match in re.finditer(pattern, content):
                findings.append(
                    SupplyChainFinding(
                        title="Potential credential exposed in manifest",
                        severity="critical",
                        category="secrets",
                        description="A credential-like pattern was detected. Verify the finding without exposing the value.",
                        source_file=source_name,
                        rule_id="SC-007",
                        evidence={
                            "pattern": label,
                            "line": content.count("\n", 0, match.start()) + 1,
                            "value_redacted": True,
                        },
                        recommendation="Remove the secret from source history and rotate it using the approved incident process.",
                    )
                )
        unique = self.deduplicate(findings)
        self.findings.extend(unique)
        return {
            "findings": [item.to_dict() for item in unique],
            "finding_count": len(unique),
        }

    def deduplicate(
        self,
        findings: list[SupplyChainFinding],
    ) -> list[SupplyChainFinding]:
        unique: dict[tuple[str, str, str | None, str | None], SupplyChainFinding] = {}
        for item in findings:
            key = (item.title, item.category, item.package, item.rule_id)
            unique[key] = item
        return list(unique.values())

    def summarize(
        self,
        findings: list[SupplyChainFinding],
    ) -> dict[str, int]:
        result = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "unknown": 0,
        }
        for item in findings:
            severity = item.severity.lower()
            result[severity if severity in result else "unknown"] += 1
        return result

    def export_findings(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "findings": [item.to_dict() for item in self.findings],
            "summary": self.summarize(self.findings),
        }
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        temporary.replace(target)

    def clear_findings(self) -> None:
        self.findings.clear()