from depcheck.analyzer import (
    classify_risk,
    extract_aliases,
    extract_affected_ranges,
    extract_affected_versions,
    extract_cwe_ids,
    extract_cvss_vector,
    extract_fixed_version,
    extract_references,
    extract_severity,
    generate_explanation,
    generate_recommendation,
)


def test_critical_severity():
    assert (
        classify_risk("CRITICAL")
        == "Critical"
    )


def test_high_severity():
    assert (
        classify_risk("HIGH")
        == "High"
    )


def test_medium_severity():
    assert (
        classify_risk("MEDIUM")
        == "Medium"
    )


def test_low_severity():
    assert (
        classify_risk("LOW")
        == "Low"
    )


def test_unknown_severity():
    assert (
        classify_risk(None)
        == "Unknown"
    )


def test_cvss_score_critical():
    assert (
        classify_risk("9.8")
        == "Critical"
    )


def test_cvss_score_high():
    assert (
        classify_risk("7.5")
        == "High"
    )


def test_cvss_score_medium():
    assert (
        classify_risk("5.0")
        == "Medium"
    )


def test_cvss_score_low():
    assert (
        classify_risk("2.5")
        == "Low"
    )


def test_extract_severity():
    vulnerability = {
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "HIGH",
            }
        ]
    }

    assert (
        extract_severity(
            vulnerability
        )
        == "HIGH"
    )


def test_extract_severity_when_missing():
    vulnerability = {}

    assert (
        extract_severity(
            vulnerability
        )
        is None
    )


def test_extract_cvss_vector():
    vulnerability = {
        "severity": [
            {
                "type": "CVSS_V3",
                "score": (
                    "CVSS:3.1/"
                    "AV:N/AC:L/"
                    "PR:N/UI:N/"
                    "S:U/C:H/I:H/A:H"
                ),
            }
        ]
    }

    assert (
        extract_cvss_vector(
            vulnerability
        )
        == (
            "CVSS:3.1/"
            "AV:N/AC:L/"
            "PR:N/UI:N/"
            "S:U/C:H/I:H/A:H"
        )
    )


def test_extract_fixed_version():
    vulnerability = {
        "affected": [
            {
                "ranges": [
                    {
                        "events": [
                            {
                                "introduced": "0"
                            },
                            {
                                "fixed": "2.20.0"
                            }
                        ]
                    }
                ]
            }
        ]
    }

    assert (
        extract_fixed_version(
            vulnerability
        )
        == "2.20.0"
    )


def test_fixed_version_when_missing():
    vulnerability = {
        "affected": []
    }

    assert (
        extract_fixed_version(
            vulnerability
        )
        is None
    )


def test_extract_aliases():
    vulnerability = {
        "aliases": [
            "CVE-2025-1234",
            "GHSA-aaaa-bbbb-cccc",
        ]
    }

    assert extract_aliases(
        vulnerability
    ) == [
        "CVE-2025-1234",
        "GHSA-aaaa-bbbb-cccc",
    ]


def test_extract_affected_versions():
    vulnerability = {
        "affected": [
            {
                "versions": [
                    "1.0.0",
                    "1.1.0",
                ]
            }
        ]
    }

    assert (
        extract_affected_versions(
            vulnerability
        )
        == [
            "1.0.0",
            "1.1.0",
        ]
    )


def test_extract_affected_ranges():
    vulnerability = {
        "affected": [
            {
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {
                                "introduced": "0"
                            },
                            {
                                "fixed": "2.0.0"
                            },
                        ],
                    }
                ]
            }
        ]
    }

    result = extract_affected_ranges(
        vulnerability
    )

    assert len(result) == 1
    assert "ECOSYSTEM" in result[0]
    assert "introduced:0" in result[0]
    assert "fixed:2.0.0" in result[0]


def test_extract_references():
    vulnerability = {
        "references": [
            {
                "type": "ADVISORY",
                "url": (
                    "https://example.com/advisory"
                ),
            },
            {
                "type": "WEB",
                "url": (
                    "https://example.com"
                ),
            },
        ]
    }

    result = extract_references(
        vulnerability
    )

    assert result == [
        {
            "type": "ADVISORY",
            "url": (
                "https://example.com/advisory"
            ),
        },
        {
            "type": "WEB",
            "url": (
                "https://example.com"
            ),
        },
    ]


def test_extract_cwe_ids():
    vulnerability = {
        "database_specific": {
            "cwe_ids": [
                "CWE-79",
                "CWE-89",
            ]
        }
    }

    result = extract_cwe_ids(
        vulnerability
    )

    assert result == [
        "CWE-79",
        "CWE-89",
    ]


def test_generate_explanation():
    explanation = generate_explanation(
        "TEST-001",
        "Example security vulnerability.",
        "High",
    )

    assert "High risk" in explanation

    assert (
        "Example security vulnerability."
        in explanation
    )


def test_generate_recommendation_with_fix():
    result = generate_recommendation(
        "2.20.0",
        "High",
    )

    assert "2.20.0" in result
    assert "Upgrade" in result


def test_generate_recommendation_without_fix():
    result = generate_recommendation(
        None,
        "Critical",
    )

    assert "No fixed version" in result