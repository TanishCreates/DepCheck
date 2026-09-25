from packaging.version import (
    Version,
    InvalidVersion,
)

from depcheck.models import (
    Dependency,
    DependencyReport,
    Vulnerability,
)

from depcheck.osv_client import (
    query_package,
)


RISK_PRIORITY = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Unknown": 0,
}


def extract_vulnerabilities(data):
    if not isinstance(data, dict):
        return []

    vulnerabilities = data.get(
        "vulns",
        [],
    )

    if not isinstance(
        vulnerabilities,
        list,
    ):
        return []

    return vulnerabilities


def extract_severity(vulnerability):
    severity_entries = vulnerability.get(
        "severity",
        [],
    )

    if not isinstance(
        severity_entries,
        list,
    ):
        return None

    for entry in severity_entries:

        if not isinstance(
            entry,
            dict,
        ):
            continue

        score = entry.get("score")

        if score:
            return str(score)

    return None


def extract_cvss_vector(vulnerability):
    severity_entries = vulnerability.get(
        "severity",
        [],
    )

    if not isinstance(
        severity_entries,
        list,
    ):
        return None

    for entry in severity_entries:

        if not isinstance(
            entry,
            dict,
        ):
            continue

        score = entry.get("score")

        if not score:
            continue

        score = str(score)

        if score.startswith("CVSS:"):
            return score

    return None


def classify_risk(severity):
    if not severity:
        return "Unknown"

    severity_text = str(
        severity
    ).upper()

    if "CRITICAL" in severity_text:
        return "Critical"

    if "HIGH" in severity_text:
        return "High"

    if "MEDIUM" in severity_text:
        return "Medium"

    if "LOW" in severity_text:
        return "Low"

    try:
        score = float(severity)

        if score >= 9.0:
            return "Critical"

        if score >= 7.0:
            return "High"

        if score >= 4.0:
            return "Medium"

        if score > 0:
            return "Low"

    except (
        ValueError,
        TypeError,
    ):
        pass

    return "Unknown"


def extract_fixed_version(
    vulnerability
):
    versions = []

    affected = vulnerability.get(
        "affected",
        [],
    )

    if not isinstance(
        affected,
        list,
    ):
        return None

    for affected_package in affected:

        if not isinstance(
            affected_package,
            dict,
        ):
            continue

        ranges = affected_package.get(
            "ranges",
            [],
        )

        if not isinstance(
            ranges,
            list,
        ):
            continue

        for range_data in ranges:

            if not isinstance(
                range_data,
                dict,
            ):
                continue

            events = range_data.get(
                "events",
                [],
            )

            if not isinstance(
                events,
                list,
            ):
                continue

            for event in events:

                if not isinstance(
                    event,
                    dict,
                ):
                    continue

                fixed = event.get(
                    "fixed"
                )

                if fixed:
                    versions.append(
                        str(fixed)
                    )

    if not versions:
        return None

    try:
        versions.sort(
            key=lambda value: Version(value)
        )

    except InvalidVersion:
        versions.sort()

    return versions[0]


def extract_aliases(
    vulnerability
):
    aliases = vulnerability.get(
        "aliases",
        [],
    )

    if not isinstance(
        aliases,
        list,
    ):
        return []

    return [
        str(alias)
        for alias in aliases
        if alias
    ]


def extract_cwe_ids(
    vulnerability
):
    cwe_ids = set()

    def collect_from_value(value):
        if isinstance(
            value,
            str,
        ):
            if value.upper().startswith(
                "CWE-"
            ):
                cwe_ids.add(
                    value.upper()
                )

        elif isinstance(
            value,
            list,
        ):
            for item in value:
                collect_from_value(item)

        elif isinstance(
            value,
            dict,
        ):
            for key, item in value.items():

                key_lower = str(
                    key
                ).lower()

                if (
                    "cwe" in key_lower
                    or "weakness" in key_lower
                ):
                    collect_from_value(item)

    collect_from_value(
        vulnerability.get(
            "database_specific",
            {},
        )
    )

    affected = vulnerability.get(
        "affected",
        [],
    )

    collect_from_value(
        affected
    )

    return sorted(
        cwe_ids
    )


def extract_affected_versions(
    vulnerability
):
    versions = set()

    affected = vulnerability.get(
        "affected",
        [],
    )

    if not isinstance(
        affected,
        list,
    ):
        return []

    for affected_package in affected:

        if not isinstance(
            affected_package,
            dict,
        ):
            continue

        package_versions = (
            affected_package.get(
                "versions",
                [],
            )
        )

        if isinstance(
            package_versions,
            list,
        ):
            for version in package_versions:

                if version:
                    versions.add(
                        str(version)
                    )

    return sorted(
        versions
    )


def extract_affected_ranges(
    vulnerability
):
    ranges_output = []

    affected = vulnerability.get(
        "affected",
        [],
    )

    if not isinstance(
        affected,
        list,
    ):
        return []

    for affected_package in affected:

        if not isinstance(
            affected_package,
            dict,
        ):
            continue

        ranges = affected_package.get(
            "ranges",
            [],
        )

        if not isinstance(
            ranges,
            list,
        ):
            continue

        for range_data in ranges:

            if not isinstance(
                range_data,
                dict,
            ):
                continue

            range_type = range_data.get(
                "type",
                "UNKNOWN",
            )

            events = range_data.get(
                "events",
                [],
            )

            event_text = []

            if isinstance(
                events,
                list,
            ):
                for event in events:

                    if not isinstance(
                        event,
                        dict,
                    ):
                        continue

                    if "introduced" in event:
                        event_text.append(
                            f"introduced:"
                            f"{event['introduced']}"
                        )

                    if "fixed" in event:
                        event_text.append(
                            f"fixed:"
                            f"{event['fixed']}"
                        )

                    if "last_affected" in event:
                        event_text.append(
                            "last_affected:"
                            f"{event['last_affected']}"
                        )

            if event_text:

                ranges_output.append(
                    f"{range_type}: "
                    + " → ".join(event_text)
                )

    return ranges_output


def extract_references(
    vulnerability
):
    references = vulnerability.get(
        "references",
        [],
    )

    if not isinstance(
        references,
        list,
    ):
        return []

    result = []

    for reference in references:

        if not isinstance(
            reference,
            dict,
        ):
            continue

        url = reference.get(
            "url"
        )

        if not url:
            continue

        result.append(
            {
                "type": str(
                    reference.get(
                        "type",
                        "UNKNOWN",
                    )
                ),
                "url": str(url),
            }
        )

    return result


def generate_explanation(
    vulnerability_id,
    summary,
    risk_level,
):
    if summary:
        explanation = summary.strip()

    else:
        explanation = (
            "A known security vulnerability "
            "has been reported for this "
            "dependency."
        )

    if risk_level == "Critical":

        prefix = (
            "This is classified as Critical. "
            "It should be investigated and "
            "fixed as soon as possible."
        )

    elif risk_level == "High":

        prefix = (
            "This is classified as High risk. "
            "It should be prioritized for "
            "remediation."
        )

    elif risk_level == "Medium":

        prefix = (
            "This is classified as Medium risk. "
            "Review the affected dependency "
            "and available fix."
        )

    elif risk_level == "Low":

        prefix = (
            "This is classified as Low risk. "
            "It should still be tracked and "
            "updated when practical."
        )

    else:

        prefix = (
            "The severity could not be determined "
            "from the available vulnerability data."
        )

    return (
        f"{prefix} {explanation}"
    )


def generate_recommendation(
    fixed_version,
    risk_level,
):
    if fixed_version:

        return (
            f"Upgrade this dependency to "
            f"version {fixed_version} or later "
            f"when compatible with the project."
        )

    if risk_level == "Critical":

        return (
            "No fixed version was identified. "
            "Investigate the advisory and "
            "consider replacing or removing "
            "the affected dependency."
        )

    if risk_level == "High":

        return (
            "No fixed version was identified. "
            "Review the advisory and consider "
            "an alternative or mitigation."
        )

    return (
        "Review the vulnerability details "
        "and available remediation options."
    )


def analyze_dependency(
    name,
    version,
    line,
    requirement="",
    version_specifier="",
):
    dependency = Dependency(
        name=name,
        version=version,
        line=line,
        requirement=requirement,
        version_specifier=(
            version_specifier
        ),
    )

    try:

        data = query_package(
            name,
            version,
        )

    except Exception as exc:

        print(
            f"[ANALYZER] Failed to scan "
            f"{name}=={version}: {exc}"
        )

        return DependencyReport(
            dependency=dependency,
            vulnerabilities=[],
        )

    raw_vulnerabilities = (
        extract_vulnerabilities(data)
    )

    vulnerabilities = []

    for raw in raw_vulnerabilities:

        vulnerability_id = raw.get(
            "id",
            "UNKNOWN",
        )

        summary = raw.get(
            "summary",
            "",
        )

        details = raw.get(
            "details",
            "",
        )

        severity = extract_severity(
            raw
        )

        risk_level = classify_risk(
            severity
        )

        fixed_version = (
            extract_fixed_version(raw)
        )

        aliases = extract_aliases(
            raw
        )

        cvss_vector = (
            extract_cvss_vector(raw)
        )

        cwe_ids = extract_cwe_ids(
            raw
        )

        affected_versions = (
            extract_affected_versions(
                raw
            )
        )

        affected_ranges = (
            extract_affected_ranges(
                raw
            )
        )

        references = (
            extract_references(
                raw
            )
        )

        explanation = (
            generate_explanation(
                vulnerability_id,
                summary,
                risk_level,
            )
        )

        recommendation = (
            generate_recommendation(
                fixed_version,
                risk_level,
            )
        )

        vulnerability = Vulnerability(
            id=vulnerability_id,
            summary=summary,
            severity=severity,
            fixed_version=fixed_version,
            risk_level=risk_level,
            aliases=aliases,
            details=details,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            affected_versions=(
                affected_versions
            ),
            affected_ranges=(
                affected_ranges
            ),
            references=references,
            explanation=explanation,
            recommendation=(
                recommendation
            ),
        )

        vulnerabilities.append(
            vulnerability
        )

    vulnerabilities.sort(
        key=lambda vulnerability:
            risk_priority(
                vulnerability.risk_level
            ),
        reverse=True,
    )

    return DependencyReport(
        dependency=dependency,
        vulnerabilities=vulnerabilities,
    )


def risk_priority(
    risk_level
):
    return RISK_PRIORITY.get(
        risk_level,
        0,
    )