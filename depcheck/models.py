from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Dependency:
    name: str
    version: str
    line: int
    requirement: str = ""
    version_specifier: str = ""


@dataclass
class Vulnerability:
    id: str
    summary: str
    severity: Optional[str]
    fixed_version: Optional[str]

    risk_level: str = "Unknown"

    aliases: list[str] = field(
        default_factory=list
    )

    details: str = ""

    cvss_vector: Optional[str] = None

    cwe_ids: list[str] = field(
        default_factory=list
    )

    affected_versions: list[str] = field(
        default_factory=list
    )

    affected_ranges: list[str] = field(
        default_factory=list
    )

    references: list[dict] = field(
        default_factory=list
    )

    explanation: str = ""

    recommendation: str = ""


@dataclass
class DependencyReport:
    dependency: Dependency
    vulnerabilities: list[Vulnerability]


@dataclass
class SkippedRequirement:
    line: int
    text: str
    reason: str