from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class RiskAssessment:
    subject: str
    score: float
    severity: str
    confidence: float
    factors: dict[str, float] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)
    assessed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RiskScoringEngine:
    def __init__(
        self,
        config: dict[str, Any] | None = None,
        policies: dict[str, Any] | None = None,
        rules: dict[str, Any] | None = None,
    ) -> None:
        self.config = config or {}
        self.policies = policies or {}
        self.rules = rules or {}
        self.history: list[RiskAssessment] = []
        self.weights = {
            "severity": 0.30,
            "exploitability": 0.20,
            "privilege": 0.15,
            "exposure": 0.15,
            "integrity": 0.10,
            "confidence": 0.10,
        }
        configured = self.policies.get("risk_scoring", {})
        configured_weights = configured.get("weights", {})
        for name, value in configured_weights.items():
            try:
                number = float(value)
            except (ValueError, TypeError):
                continue
            if math.isfinite(number) and number >= 0:
                self.weights[name] = number
        self.thresholds = {
            "critical": 85.0,
            "high": 65.0,
            "medium": 40.0,
            "low": 15.0,
        }
        configured_thresholds = configured.get("thresholds", {})
        for name, value in configured_thresholds.items():
            try:
                number = float(value)
            except (ValueError, TypeError):
                continue
            if math.isfinite(number) and 0 <= number <= 100:
                self.thresholds[name.lower()] = number

    def score(self, findings: list[Any]) -> list[dict[str, Any]]:
        return self.score_findings(findings)

    def assess(self, findings: list[Any]) -> list[dict[str, Any]]:
        return self.score_findings(findings)

    def score_all(self, findings: list[Any]) -> list[dict[str, Any]]:
        return self.score_findings(findings)

    def score_findings(self, findings: list[Any]) -> list[dict[str, Any]]:
        results = []
        for raw in findings:
            finding = self.normalize_finding(raw)
            assessment = self.assess_finding(finding)
            results.append(assessment.to_dict())
        return results

    def normalize_finding(self, raw: Any) -> dict[str, Any]:
        if hasattr(raw, "to_dict"):
            raw = raw.to_dict()
        elif hasattr(raw, "__dataclass_fields__"):
            raw = asdict(raw)
        if not isinstance(raw, dict):
            return {
                "title": str(raw),
                "severity": "unknown",
                "category": "unknown",
                "description": "",
                "evidence": {},
            }
        result = dict(raw)
        result.setdefault("title", "Unspecified finding")
        result.setdefault("severity", "unknown")
        result.setdefault("category", "unknown")
        result.setdefault("description", "")
        result.setdefault("evidence", {})
        return result

    def assess_finding(self, finding: dict[str, Any]) -> RiskAssessment:
        severity = self.severity_factor(finding.get("severity"))
        exploitability = self.exploitability_factor(finding)
        privilege = self.privilege_factor(finding)
        exposure = self.exposure_factor(finding)
        integrity = self.integrity_factor(finding)
        confidence = self.confidence_factor(finding)
        factors = {
            "severity": severity,
            "exploitability": exploitability,
            "privilege": privilege,
            "exposure": exposure,
            "integrity": integrity,
            "confidence": confidence,
        }
        score = self.weighted_score(factors)
        level = self.severity_from_score(score)
        recommendations = self.recommendations_for(finding, level)
        assessment = RiskAssessment(
            subject=str(
                finding.get("package")
                or finding.get("title")
                or finding.get("subject")
                or "unknown"
            ),
            score=round(score, 2),
            severity=level,
            confidence=round(confidence / 100, 3),
            factors={key: round(value, 2) for key, value in factors.items()},
            evidence={
                "original_severity": finding.get("severity"),
                "category": finding.get("category"),
                "rule_id": finding.get("rule_id"),
                "advisory_id": finding.get("advisory_id"),
                "source_file": finding.get("source_file"),
                "description": finding.get("description"),
                "evidence": finding.get("evidence", {}),
            },
            recommendations=recommendations,
        )
        self.history.append(assessment)
        return assessment

    def weighted_score(self, factors: dict[str, float]) -> float:
        active_weights = {
            key: value
            for key, value in self.weights.items()
            if key in factors and value > 0
        }
        total_weight = sum(active_weights.values())
        if total_weight <= 0:
            return 0.0
        result = sum(
            factors[key] * weight
            for key, weight in active_weights.items()
        ) / total_weight
        return max(0.0, min(100.0, result))

    def severity_factor(self, severity: Any) -> float:
        values = {
            "critical": 100.0,
            "high": 80.0,
            "medium": 55.0,
            "moderate": 55.0,
            "low": 30.0,
            "info": 10.0,
            "informational": 10.0,
            "unknown": 45.0,
        }
        return values.get(str(severity or "unknown").lower(), 45.0)

    def exploitability_factor(self, finding: dict[str, Any]) -> float:
        evidence = self.safe_mapping(finding.get("evidence"))
        cvss = self.safe_float(finding.get("cvss_score"))
        if cvss is None:
            cvss = self.safe_float(evidence.get("cvss_score"))
        if cvss is not None:
            return max(0.0, min(100.0, cvss * 10))
        category = str(finding.get("category", "")).lower()
        title = str(finding.get("title", "")).lower()
        description = str(finding.get("description", "")).lower()
        text = f"{category} {title} {description}"
        if any(value in text for value in ("remote code execution", "rce", "code execution")):
            return 100.0
        if any(value in text for value in ("known exploited", "actively exploited")):
            return 100.0
        if any(value in text for value in ("credential", "private key", "secret")):
            return 90.0
        if any(value in text for value in ("untrusted source", "malicious package")):
            return 90.0
        if "vulnerability" in text:
            return 65.0
        if "provenance" in text or "integrity" in text:
            return 55.0
        return 35.0

    def privilege_factor(self, finding: dict[str, Any]) -> float:
        evidence = self.safe_mapping(finding.get("evidence"))
        values = [
            finding.get("privilege_level"),
            evidence.get("privilege_level"),
            evidence.get("permission_level"),
        ]
        combined = " ".join(str(value).lower() for value in values if value is not None)
        if any(value in combined for value in ("administrator", "owner", "root", "superuser")):
            return 100.0
        if any(value in combined for value in ("write", "deploy", "publish", "release")):
            return 80.0
        if any(value in combined for value in ("privileged", "elevated", "maintainer")):
            return 75.0
        if any(value in combined for value in ("read", "viewer")):
            return 35.0
        category = str(finding.get("category", "")).lower()
        if category in {"secrets", "provenance", "artifact_integrity"}:
            return 65.0
        return 40.0

    def exposure_factor(self, finding: dict[str, Any]) -> float:
        evidence = self.safe_mapping(finding.get("evidence"))
        exposed = evidence.get("publicly_exposed")
        internet_facing = evidence.get("internet_facing")
        if exposed is True or internet_facing is True:
            return 100.0
        if exposed is False and internet_facing is False:
            return 25.0
        source = str(evidence.get("source_url", "")).lower()
        if source.startswith("http://"):
            return 75.0
        if source.startswith("https://"):
            return 50.0
        return 40.0

    def integrity_factor(self, finding: dict[str, Any]) -> float:
        category = str(finding.get("category", "")).lower()
        title = str(finding.get("title", "")).lower()
        text = f"{category} {title}"
        if any(value in text for value in ("hash mismatch", "malicious package", "tampered")):
            return 100.0
        if any(value in text for value in ("missing checksum", "integrity hash", "untrusted source")):
            return 85.0
        if any(value in text for value in ("vcs", "mutable version", "unpinned")):
            return 70.0
        if any(value in text for value in ("license", "deprecated")):
            return 30.0
        return 45.0

    def confidence_factor(self, finding: dict[str, Any]) -> float:
        evidence = self.safe_mapping(finding.get("evidence"))
        confidence = self.safe_float(finding.get("confidence"))
        if confidence is None:
            confidence = self.safe_float(evidence.get("confidence"))
        if confidence is not None:
            if 0 <= confidence <= 1:
                confidence *= 100
            return max(0.0, min(100.0, confidence))
        advisory = finding.get("advisory_id")
        rule_id = finding.get("rule_id")
        if advisory and evidence:
            return 95.0
        if rule_id and evidence:
            return 85.0
        if evidence:
            return 70.0
        return 45.0

    def severity_from_score(self, score: float) -> str:
        if score >= self.thresholds.get("critical", 85):
            return "critical"
        if score >= self.thresholds.get("high", 65):
            return "high"
        if score >= self.thresholds.get("medium", 40):
            return "medium"
        if score >= self.thresholds.get("low", 15):
            return "low"
        return "info"

    def recommendations_for(
        self,
        finding: dict[str, Any],
        severity: str,
    ) -> list[str]:
        category = str(finding.get("category", "")).lower()
        evidence = self.safe_mapping(finding.get("evidence"))
        recommendations = []
        if category == "vulnerability":
            recommendations.append(
                "Validate the advisory against the installed package version and upgrade to a verified fixed release when available."
            )
        if category in {"provenance", "artifact_integrity", "package_integrity"}:
            recommendations.append(
                "Verify package origin and artifact integrity using trusted registry metadata and approved checksums."
            )
        if category in {"secrets", "credential_exposure"}:
            recommendations.append(
                "Protect the affected credential, rotate it if exposure is confirmed, and remove it from source history through the approved process."
            )
        if category == "licensing":
            recommendations.append(
                "Review license obligations with the software governance or legal team."
            )
        if category in {"dependency_integrity", "reproducibility"}:
            recommendations.append(
                "Pin dependencies and regenerate lockfiles using the approved package manager."
            )
        if severity in {"critical", "high"}:
            recommendations.append(
                "Prioritize investigation and require an authorized owner to approve remediation."
            )
        if not recommendations:
            recommendations.append(
                "Validate the finding, document the evidence, and assign an accountable owner for review."
            )
        if evidence.get("source_file"):
            recommendations.append(
                "Confirm the finding against the referenced source file and the resolved dependency inventory."
            )
        return list(dict.fromkeys(recommendations))

    def score_identity_or_package(self, subject: dict[str, Any]) -> dict[str, Any]:
        finding = {
            "title": subject.get("title", subject.get("name", "Risk subject")),
            "severity": subject.get("severity", "unknown"),
            "category": subject.get("category", "supply_chain"),
            "description": subject.get("description", ""),
            "package": subject.get("package", subject.get("name")),
            "evidence": subject.get("evidence", subject),
            "cvss_score": subject.get("cvss_score"),
            "advisory_id": subject.get("advisory_id"),
            "rule_id": subject.get("rule_id"),
        }
        return self.assess_finding(finding).to_dict()

    def rank_findings(self, findings: list[Any]) -> list[dict[str, Any]]:
        ranked = self.score_findings(findings)
        ranked.sort(
            key=lambda item: (
                item.get("score", 0),
                item.get("confidence", 0),
            ),
            reverse=True,
        )
        for position, item in enumerate(ranked, start=1):
            item["rank"] = position
        return ranked

    def aggregate_package_risk(
        self,
        assessments: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if not assessments:
            return {
                "score": 0.0,
                "severity": "info",
                "finding_count": 0,
                "maximum_score": 0.0,
            }
        scores = [
            max(0.0, min(100.0, self.safe_float(item.get("score")) or 0.0))
            for item in assessments
        ]
        maximum = max(scores)
        residual = 1.0
        for score in scores:
            residual *= 1.0 - score / 100.0
        combined = max(maximum, (1.0 - residual) * 100.0 * 0.65)
        return {
            "score": round(min(combined, 100.0), 2),
            "severity": self.severity_from_score(combined),
            "finding_count": len(assessments),
            "maximum_score": round(maximum, 2),
            "average_score": round(sum(scores) / len(scores), 2),
        }

    def group_by_severity(
        self,
        assessments: list[dict[str, Any]],
    ) -> dict[str, list[dict[str, Any]]]:
        groups = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }
        for assessment in assessments:
            level = str(assessment.get("severity", "info")).lower()
            groups.setdefault(level, []).append(assessment)
        return groups

    def summary(self, assessments: list[dict[str, Any]]) -> dict[str, Any]:
        groups = self.group_by_severity(assessments)
        scores = [
            self.safe_float(item.get("score")) or 0.0
            for item in assessments
        ]
        return {
            "total_assessments": len(assessments),
            "critical": len(groups.get("critical", [])),
            "high": len(groups.get("high", [])),
            "medium": len(groups.get("medium", [])),
            "low": len(groups.get("low", [])),
            "info": len(groups.get("info", [])),
            "average_score": round(sum(scores) / len(scores), 2) if scores else 0.0,
            "maximum_score": round(max(scores), 2) if scores else 0.0,
        }

    def export_json(
        self,
        path: str | Path,
        assessments: list[dict[str, Any]] | None = None,
    ) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        values = assessments
        if values is None:
            values = [item.to_dict() for item in self.history]
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": self.summary(values),
            "assessments": values,
        }
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        temporary.replace(target)

    def export_markdown(
        self,
        path: str | Path,
        assessments: list[dict[str, Any]] | None = None,
    ) -> None:
        values = assessments
        if values is None:
            values = [item.to_dict() for item in self.history]
        summary = self.summary(values)
        lines = [
            "# Supply-Chain Risk Assessment",
            "",
            f"- Generated: {datetime.now(timezone.utc).isoformat()}",
            f"- Assessments: {summary['total_assessments']}",
            f"- Critical: {summary['critical']}",
            f"- High: {summary['high']}",
            f"- Medium: {summary['medium']}",
            f"- Low: {summary['low']}",
            f"- Average score: {summary['average_score']}",
            "",
            "| Rank | Subject | Score | Severity | Confidence |",
            "|---:|---|---:|---|---:|",
        ]
        ranked = sorted(
            values,
            key=lambda item: self.safe_float(item.get("score")) or 0.0,
            reverse=True,
        )
        for rank, item in enumerate(ranked, start=1):
            lines.append(
                f"| {rank} | {item.get('subject', 'unknown')} | "
                f"{item.get('score', 0)} | {item.get('severity', 'unknown')} | "
                f"{item.get('confidence', 0)} |"
            )
        for rank, item in enumerate(ranked, start=1):
            lines.extend(
                [
                    "",
                    f"## {rank}. {item.get('subject', 'unknown')}",
                    "",
                    f"Score: **{item.get('score', 0)}**",
                    "",
                    f"Severity: **{item.get('severity', 'unknown')}**",
                    "",
                    "### Contributing Factors",
                    "",
                ]
            )
            for factor, value in item.get("factors", {}).items():
                lines.append(f"- {factor}: {value}")
            lines.extend(["", "### Recommendations", ""])
            lines.extend(
                f"- {value}" for value in item.get("recommendations", [])
            )
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
        temporary.replace(target)

    def safe_mapping(self, value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def safe_float(self, value: Any) -> float | None:
        if value is None or isinstance(value, bool):
            return None
        try:
            result = float(value)
        except (ValueError, TypeError, OverflowError):
            return None
        return result if math.isfinite(result) else None

    def clear_history(self) -> None:
        self.history.clear()

    def get_history(self) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self.history]