from depcheck.parsers import parse_dependency_file
from depcheck.analyzer import analyze_dependency


def scan_file(file_path):
    packages, skipped = parse_dependency_file(file_path)

    reports = []

    for package in packages:
        report = analyze_dependency(
            name=package["name"],
            version=package["version"],
            line=package.get("line", 0),
            requirement=package.get("requirement", ""),
            version_specifier=package.get(
                "version_specifier",
                "",
            ),
        )

        reports.append(report)

    return reports, skipped


def get_all_vulnerabilities(reports):
    """
    Convert vulnerability results into dictionaries.

    The web application expects:
        item["dependency"]
        item["vulnerability"]
    """

    vulnerabilities = []

    for report in reports:
        for vulnerability in report.vulnerabilities:

            vulnerabilities.append({
                "dependency": report.dependency,
                "vulnerability": vulnerability,
            })

    return vulnerabilities


def print_report(reports, skipped):

    total_dependencies = len(reports)

    vulnerable_dependencies = sum(
        1
        for report in reports
        if report.vulnerabilities
    )

    all_vulnerabilities = get_all_vulnerabilities(
        reports
    )

    total_vulnerabilities = len(
        all_vulnerabilities
    )

    print("\n" + "=" * 60)
    print("DEPCheck SECURITY REPORT")
    print("=" * 60)

    print(
        f"\nDependencies checked: "
        f"{total_dependencies}"
    )

    print(
        f"Vulnerable dependencies: "
        f"{vulnerable_dependencies}"
    )

    print(
        f"Total vulnerabilities: "
        f"{total_vulnerabilities}"
    )

    print(
        f"Skipped requirements: "
        f"{len(skipped)}"
    )

    if skipped:

        print("\nSKIPPED REQUIREMENTS")
        print("-" * 60)

        for item in skipped:

            print(
                f"Line {item.line}: "
                f"{item.text}"
            )

            print(
                f"  Reason: "
                f"{item.reason}"
            )

    if not all_vulnerabilities:

        print("\nNo vulnerabilities found.")

        return

    print("\nFIX THESE FIRST")
    print("-" * 60)

    sorted_vulnerabilities = sorted(
        all_vulnerabilities,
        key=lambda item: {
            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1,
            "Unknown": 0,
            "None": 0,
        }.get(
            item["vulnerability"].risk_level,
            0,
        ),
        reverse=True,
    )

    for item in sorted_vulnerabilities[:10]:

        dependency = item["dependency"]
        vulnerability = item["vulnerability"]

        print(
            f"\n[{vulnerability.risk_level}] "
            f"{dependency.name} "
            f"{dependency.version}"
        )

        print(
            f"ID: {vulnerability.id}"
        )

        print(
            f"Summary: "
            f"{vulnerability.summary}"
        )

        print(
            f"Fixed version: "
            f"{vulnerability.fixed_version or 'Not available'}"
        )

    print("\n" + "=" * 60)


def main():

    import sys

    if len(sys.argv) != 2:

        print(
            "Usage: "
            "python -m depcheck.cli "
            "<requirements.txt>"
        )

        return

    file_path = sys.argv[1]

    reports, skipped = scan_file(
        file_path
    )

    print_report(
        reports,
        skipped,
    )


if __name__ == "__main__":
    main()