from __future__ import annotations

import json
import re
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version


@dataclass
class DependencyRecord:
    name: str
    version: str | None
    source_file: str
    ecosystem: str
    direct: bool = True
    pinned: bool = False
    source_url: str | None = None
    vcs: bool = False
    commit: str | None = None
    hashes: list[str] = field(default_factory=list)
    extras: list[str] = field(default_factory=list)
    markers: str | None = None
    license: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DependencyIssue:
    title: str
    severity: str
    category: str
    description: str
    package: str | None = None
    rule_id: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DependencyAnalyzer:
    def __init__(
        self,
        config: dict[str, Any] | None = None,
        policies: dict[str, Any] | None = None,
    ) -> None:
        self.config = config or {}
        self.policies = policies or {}
        self.dependencies: list[DependencyRecord] = []
        self.issues: list[DependencyIssue] = []
        self.max_depth = int(
            self.policies.get("dependency_policy", {}).get(
                "maximum_dependency_depth", 50
            )
        )

    def analyze_file(self, path: str | Path) -> dict[str, Any]:
        source = Path(path).expanduser().resolve()
        if not source.exists():
            raise FileNotFoundError(str(source))
        if not source.is_file():
            raise ValueError(f"Expected a file: {source}")
        suffix = source.suffix.lower()
        name = source.name.lower()
        if name == "requirements.txt":
            records = self.parse_requirements(source)
        elif name == "pyproject.toml":
            records = self.parse_pyproject(source)
        elif name == "pipfile":
            records = self.parse_pipfile(source)
        elif name == "pipfile.lock":
            records = self.parse_pipfile_lock(source)
        elif name == "package.json":
            records = self.parse_package_json(source)
        elif name == "package-lock.json":
            records = self.parse_package_lock(source)
        elif name == "pnpm-lock.yaml":
            records = self.parse_pnpm_lock(source)
        elif name == "pom.xml":
            records = self.parse_pom(source)
        elif name in {"cargo.toml", "cargo.lock"}:
            records = self.parse_cargo(source)
        elif name in {"go.mod", "go.sum"}:
            records = self.parse_go(source)
        else:
            records = []
            self.add_issue(
                "Unsupported dependency manifest",
                "low",
                "input",
                f"No parser is configured for {source.name}.",
                evidence={"source_file": str(source)},
            )
        self.dependencies.extend(records)
        return {
            "source_file": str(source),
            "dependencies": [item.to_dict() for item in records],
            "findings": [item.to_dict() for item in self.issues],
            "dependency_count": len(records),
        }

    def analyze_manifest(self, path: str | Path) -> dict[str, Any]:
        return self.analyze_file(path)

    def analyze(self, path: str | Path) -> dict[str, Any]:
        return self.analyze_file(path)

    def scan(self, path: str | Path) -> dict[str, Any]:
        return self.analyze_file(path)

    def add_issue(
        self,
        title: str,
        severity: str,
        category: str,
        description: str,
        package: str | None = None,
        rule_id: str | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        self.issues.append(
            DependencyIssue(
                title=title,
                severity=severity,
                category=category,
                description=description,
                package=package,
                rule_id=rule_id,
                evidence=evidence or {},
            )
        )

    def parse_requirements(self, path: Path) -> list[DependencyRecord]:
        records = []
        for line_number, raw in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-r "):
                continue
            if line.startswith(("-e ", "--editable ")):
                line = line.split(maxsplit=1)[1]
            if line.startswith(("-f ", "--find-links ")):
                continue
            if line.startswith("--index-url ") or line.startswith("--extra-index-url "):
                continue
            try:
                requirement = Requirement(line)
            except InvalidRequirement:
                self.add_issue(
                    "Invalid requirement syntax",
                    "medium",
                    "dependency_integrity",
                    f"Requirement line {line_number} could not be parsed.",
                    evidence={"source_file": str(path), "line": line_number},
                )
                continue
            exact = [
                spec.version
                for spec in requirement.specifier
                if spec.operator == "==" and "*" not in spec.version
            ]
            version = exact[0] if len(exact) == 1 else None
            url = requirement.url
            vcs = bool(url and urlparse(url).scheme in {"git+https", "git+ssh", "git"})
            commit = None
            if url:
                match = re.search(r"@([0-9a-fA-F]{7,40})(?:#|$)", url)
                commit = match.group(1) if match else None
            hashes = re.findall(r"--hash(?:=|\s+)([A-Za-z0-9:]+)", raw)
            records.append(
                DependencyRecord(
                    name=requirement.name,
                    version=version,
                    source_file=str(path),
                    ecosystem="pypi",
                    pinned=version is not None,
                    source_url=url,
                    vcs=vcs,
                    commit=commit,
                    hashes=hashes,
                    extras=sorted(requirement.extras),
                    markers=str(requirement.marker) if requirement.marker else None,
                    metadata={"line": line_number, "specifier": str(requirement.specifier)},
                )
            )
            self.check_dependency(records[-1])
        return records

    def parse_pyproject(self, path: Path) -> list[DependencyRecord]:
        with path.open("rb") as stream:
            document = tomllib.load(stream)
        project = document.get("project", {})
        dependencies = list(project.get("dependencies", []))
        optional = project.get("optional-dependencies", {})
        for group in optional.values():
            if isinstance(group, list):
                dependencies.extend(group)
        poetry = document.get("tool", {}).get("poetry", {})
        poetry_dependencies = poetry.get("dependencies", {})
        for package, value in poetry_dependencies.items():
            if package.lower() == "python":
                continue
            if isinstance(value, str):
                dependencies.append(f"{package}{value if value.startswith(('=', '<', '>', '!', '~')) else '==' + value}")
            elif isinstance(value, dict):
                version = value.get("version")
                if isinstance(version, str):
                    dependencies.append(f"{package}{version}")
        records = []
        for specification in dependencies:
            try:
                requirement = Requirement(str(specification))
            except InvalidRequirement:
                continue
            exact = [
                spec.version
                for spec in requirement.specifier
                if spec.operator == "==" and "*" not in spec.version
            ]
            record = DependencyRecord(
                name=requirement.name,
                version=exact[0] if len(exact) == 1 else None,
                source_file=str(path),
                ecosystem="pypi",
                pinned=len(exact) == 1,
                source_url=requirement.url,
                extras=sorted(requirement.extras),
                markers=str(requirement.marker) if requirement.marker else None,
            )
            records.append(record)
            self.check_dependency(record)
        return records

    def parse_pipfile(self, path: Path) -> list[DependencyRecord]:
        import tomllib

        with path.open("rb") as stream:
            document = tomllib.load(stream)
        records = []
        for section_name in ("packages", "dev-packages"):
            packages = document.get(section_name, {})
            for name, specification in packages.items():
                value = specification if isinstance(specification, str) else ""
                version = value[2:] if value.startswith("==") else None
                record = DependencyRecord(
                    name=name,
                    version=version,
                    source_file=str(path),
                    ecosystem="pypi",
                    direct=True,
                    pinned=version is not None,
                    metadata={"group": section_name},
                )
                records.append(record)
                self.check_dependency(record)
        return records

    def parse_pipfile_lock(self, path: Path) -> list[DependencyRecord]:
        document = json.loads(path.read_text(encoding="utf-8"))
        records = []
        for section_name in ("default", "develop"):
            for name, details in document.get(section_name, {}).items():
                if not isinstance(details, dict):
                    continue
                version = str(details.get("version", "")).removeprefix("==")
                hashes = details.get("hashes", [])
                record = DependencyRecord(
                    name=name,
                    version=version or None,
                    source_file=str(path),
                    ecosystem="pypi",
                    pinned=bool(version),
                    source_url=details.get("index"),
                    hashes=list(hashes) if isinstance(hashes, list) else [],
                    metadata={"group": section_name},
                )
                records.append(record)
                self.check_dependency(record)
        return records

    def parse_package_json(self, path: Path) -> list[DependencyRecord]:
        document = json.loads(path.read_text(encoding="utf-8"))
        records = []
        groups = ("dependencies", "devDependencies", "optionalDependencies")
        for group in groups:
            values = document.get(group, {})
            for name, specification in values.items():
                version = self.normalize_npm_version(str(specification))
                record = DependencyRecord(
                    name=name,
                    version=version,
                    source_file=str(path),
                    ecosystem="npm",
                    pinned=version is not None,
                    metadata={"group": group, "declared_specifier": specification},
                )
                records.append(record)
                self.check_dependency(record)
        return records

    def parse_package_lock(self, path: Path) -> list[DependencyRecord]:
        document = json.loads(path.read_text(encoding="utf-8"))
        records = []
        packages = document.get("packages")
        if isinstance(packages, dict):
            for package_path, details in packages.items():
                if not package_path or not isinstance(details, dict):
                    continue
                name = details.get("name")
                if not name:
                    parts = package_path.split("node_modules/")
                    name = parts[-1] if len(parts) > 1 else package_path
                version = details.get("version")
                record = DependencyRecord(
                    name=str(name),
                    version=str(version) if version is not None else None,
                    source_file=str(path),
                    ecosystem="npm",
                    direct=package_path.count("node_modules/") <= 1,
                    pinned=version is not None,
                    source_url=details.get("resolved"),
                    hashes=[str(details["integrity"])] if details.get("integrity") else [],
                    metadata={"package_path": package_path},
                )
                records.append(record)
                self.check_dependency(record)
        else:
            for name, details in document.get("dependencies", {}).items():
                if not isinstance(details, dict):
                    continue
                version = details.get("version")
                record = DependencyRecord(
                    name=name,
                    version=str(version) if version else None,
                    source_file=str(path),
                    ecosystem="npm",
                    pinned=version is not None,
                    source_url=details.get("resolved"),
                    hashes=[str(details["integrity"])] if details.get("integrity") else [],
                )
                records.append(record)
                self.check_dependency(record)
        return records

    def parse_pnpm_lock(self, path: Path) -> list[DependencyRecord]:
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError("PyYAML is required to parse pnpm-lock.yaml") from exc
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        records = []
        packages = document.get("packages", {})
        for package_key, details in packages.items():
            if isinstance(details, str):
                version = details
            elif isinstance(details, dict):
                version = details.get("version")
            else:
                version = None
            normalized = str(package_key).lstrip("/")
            match = re.match(r"(@[^/]+/[^@]+|[^@/]+)@(.+)", normalized)
            name = match.group(1) if match else normalized
            version = str(version or (match.group(2) if match else "")) or None
            record = DependencyRecord(
                name=name,
                version=version,
                source_file=str(path),
                ecosystem="npm",
                direct=False,
                pinned=version is not None,
                metadata={"lock_key": package_key},
            )
            records.append(record)
            self.check_dependency(record)
        return records

    def parse_pom(self, path: Path) -> list[DependencyRecord]:
        import xml.etree.ElementTree as ET

        root = ET.parse(path).getroot()
        namespace = ""
        if root.tag.startswith("{"):
            namespace = root.tag.split("}", 1)[0] + "}"
        properties = {}
        for prop in root.findall(f".//{namespace}properties/*"):
            properties[prop.tag.split("}")[-1]] = prop.text or ""
        records = []
        for dependency in root.findall(f".//{namespace}dependencies/{namespace}dependency"):
            group = dependency.findtext(f"{namespace}groupId", default="")
            artifact = dependency.findtext(f"{namespace}artifactId", default="")
            version = dependency.findtext(f"{namespace}version", default="")
            version = re.sub(
                r"\$\{([^}]+)\}",
                lambda match: properties.get(match.group(1), match.group(0)),
                version,
            )
            if not artifact:
                continue
            record = DependencyRecord(
                name=f"{group}:{artifact}" if group else artifact,
                version=version or None,
                source_file=str(path),
                ecosystem="maven",
                pinned=bool(version and "${" not in version),
                metadata={
                    "group_id": group,
                    "artifact_id": artifact,
                    "scope": dependency.findtext(f"{namespace}scope"),
                },
            )
            records.append(record)
            self.check_dependency(record)
        return records

    def parse_cargo(self, path: Path) -> list[DependencyRecord]:
        if path.name.lower() == "cargo.toml":
            with path.open("rb") as stream:
                document = tomllib.load(stream)
            records = []
            for group in ("dependencies", "dev-dependencies", "build-dependencies"):
                for name, value in document.get(group, {}).items():
                    version = value if isinstance(value, str) else value.get("version")
                    record = DependencyRecord(
                        name=name,
                        version=str(version) if version else None,
                        source_file=str(path),
                        ecosystem="cargo",
                        pinned=False,
                        source_url=value.get("git") if isinstance(value, dict) else None,
                        vcs=isinstance(value, dict) and bool(value.get("git")),
                        commit=value.get("rev") if isinstance(value, dict) else None,
                        metadata={"group": group},
                    )
                    records.append(record)
                    self.check_dependency(record)
            return records
        document = tomllib.loads(path.read_text(encoding="utf-8")) if path.suffix == ".toml" else {}
        records = []
        for package in document.get("package", []):
            name = package.get("name")
            version = package.get("version")
            if not name:
                continue
            record = DependencyRecord(
                name=name,
                version=version,
                source_file=str(path),
                ecosystem="cargo",
                pinned=bool(version),
                metadata={"checksum": package.get("checksum")},
            )
            records.append(record)
            self.check_dependency(record)
        return records

    def parse_go(self, path: Path) -> list[DependencyRecord]:
        records = []
        lines = path.read_text(encoding="utf-8").splitlines()
        in_require = False
        for line_number, raw in enumerate(lines, start=1):
            line = raw.strip()
            if not line:
                continue
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue
            if line.startswith(("module ", "go ", "toolchain ", "replace ", "exclude ")):
                continue
            if line.startswith("//"):
                continue
            if line.startswith("require "):
                line = line.removeprefix("require ").strip()
            if line.startswith(")") or line.startswith("("):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            module, version = parts[0], parts[1]
            version = version.removesuffix("// indirect")
            record = DependencyRecord(
                name=module,
                version=version,
                source_file=str(path),
                ecosystem="go",
                direct=not raw.strip().endswith("// indirect"),
                pinned=bool(version),
                metadata={"line": line_number},
            )
            records.append(record)
            self.check_dependency(record)
        return records

    def normalize_npm_version(self, specification: str) -> str | None:
        value = specification.strip()
        if value.startswith(("file:", "link:", "workspace:")):
            return None
        if value.startswith(("git+", "git://", "https://", "github:")):
            return None
        if value.startswith(("^", "~", ">", "<", "*")):
            return None
        if value.startswith("npm:"):
            value = value.split("@")[-1]
        try:
            Version(value)
            return value
        except InvalidVersion:
            return None

    def check_dependency(self, dependency: DependencyRecord) -> list[DependencyIssue]:
        before = len(self.issues)
        policy = self.policies.get("dependency_policy", {})
        if policy.get("reject_unpinned_direct_dependencies") and dependency.direct:
            if not dependency.pinned:
                self.add_issue(
                    "Dependency is not exactly pinned",
                    "high",
                    "dependency_integrity",
                    "The dependency declaration does not identify one exact version.",
                    package=dependency.name,
                    rule_id="SC-002",
                    evidence={
                        "source_file": dependency.source_file,
                        "version": dependency.version,
                        "ecosystem": dependency.ecosystem,
                    },
                )
        if policy.get("reject_vcs_dependencies_without_commit"):
            if dependency.vcs and not dependency.commit:
                self.add_issue(
                    "VCS dependency lacks immutable commit",
                    "high",
                    "dependency_integrity",
                    "The source dependency does not include a detected immutable commit.",
                    package=dependency.name,
                    rule_id="SC-009",
                    evidence={"source_url": dependency.source_url},
                )
        if dependency.source_url:
            parsed = urlparse(dependency.source_url)
            if parsed.scheme in {"http", "git", "git+http"}:
                self.add_issue(
                    "Dependency source uses an insecure transport",
                    "high",
                    "provenance",
                    "The source URL uses a transport that does not provide HTTPS.",
                    package=dependency.name,
                    evidence={"source_url": dependency.source_url},
                )
        if dependency.version:
            try:
                Version(dependency.version)
            except InvalidVersion:
                if dependency.ecosystem == "pypi":
                    self.add_issue(
                        "Unrecognized Python package version",
                        "low",
                        "input_quality",
                        "The version could not be normalized using Python packaging rules.",
                        package=dependency.name,
                        evidence={"version": dependency.version},
                    )
        return self.issues[before:]

    def analyze_dependencies(self, dependencies: list[Any]) -> dict[str, Any]:
        records = []
        for value in dependencies:
            if isinstance(value, DependencyRecord):
                records.append(value)
            elif isinstance(value, dict):
                allowed = DependencyRecord.__dataclass_fields__
                fields = {key: item for key, item in value.items() if key in allowed}
                if "name" in fields and "source_file" in fields and "ecosystem" in fields:
                    records.append(DependencyRecord(**fields))
        issues = []
        for record in records:
            issues.extend(item.to_dict() for item in self.check_dependency(record))
        return {
            "dependencies": [item.to_dict() for item in records],
            "findings": issues,
            "dependency_count": len(records),
        }

    def inventory(self) -> list[dict[str, Any]]:
        unique: dict[tuple[str, str, str], DependencyRecord] = {}
        for item in self.dependencies:
            key = (item.ecosystem, item.name.lower(), item.version or "")
            unique[key] = item
        return [item.to_dict() for item in unique.values()]

    def statistics(self) -> dict[str, Any]:
        inventory = self.inventory()
        ecosystems: dict[str, int] = {}
        pinned_count = 0
        vcs_count = 0
        hash_count = 0
        for item in self.dependencies:
            ecosystems[item.ecosystem] = ecosystems.get(item.ecosystem, 0) + 1
            pinned_count += int(item.pinned)
            vcs_count += int(item.vcs)
            hash_count += int(bool(item.hashes))
        return {
            "total_records": len(self.dependencies),
            "unique_dependencies": len(inventory),
            "pinned_dependencies": pinned_count,
            "unpinned_dependencies": len(self.dependencies) - pinned_count,
            "vcs_dependencies": vcs_count,
            "dependencies_with_hashes": hash_count,
            "ecosystems": ecosystems,
            "issue_count": len(self.issues),
        }