from pathlib import Path

from depcheck.parsers import parse_requirements


SAMPLE_FILE = Path(
    "tests/sample_files/requirements-old.txt"
)


def test_exact_requirements_are_parsed():
    dependencies, skipped = parse_requirements(SAMPLE_FILE)

    names = [dependency["name"] for dependency in dependencies]

    assert "requests" in names
    assert "django" in names
    assert "jinja2" in names


def test_exact_versions_are_correct():
    dependencies, skipped = parse_requirements(SAMPLE_FILE)

    requests_dependency = next(
        dependency
        for dependency in dependencies
        if dependency["name"] == "requests"
        and dependency["version"] == "2.19.0"
    )

    assert requests_dependency["version"] == "2.19.0"


def test_version_ranges_are_skipped():
    dependencies, skipped = parse_requirements(SAMPLE_FILE)

    skipped_text = [
        item.text
        for item in skipped
    ]

    assert any(
        "flask" in text
        for text in skipped_text
    )

    assert any(
        "urllib3" in text
        for text in skipped_text
    )


def test_unversioned_packages_are_skipped():
    dependencies, skipped = parse_requirements(SAMPLE_FILE)

    skipped_text = [
        item.text
        for item in skipped
    ]

    assert any(
        "beautifulsoup4" in text
        for text in skipped_text
    )


def test_include_and_editable_lines_are_skipped():
    dependencies, skipped = parse_requirements(SAMPLE_FILE)

    skipped_text = [
        item.text
        for item in skipped
    ]

    assert any(
        "-r another.txt" in text
        for text in skipped_text
    )

    assert any(
        "-e ./local-package" in text
        for text in skipped_text
    )


def test_malformed_requirement_is_skipped():
    dependencies, skipped = parse_requirements(SAMPLE_FILE)

    skipped_text = [
        item.text
        for item in skipped
    ]

    assert any(
        "definitely not a valid requirement" in text
        for text in skipped_text
    )


def test_requirement_metadata_is_preserved():
    dependencies, skipped = parse_requirements(SAMPLE_FILE)

    requests_dependency = next(
        dependency
        for dependency in dependencies
        if dependency["name"] == "requests"
        and dependency["version"] == "2.19.0"
    )

    assert requests_dependency["requirement"] == (
        "requests==2.19.0"
    )

    assert requests_dependency["version_specifier"] == (
        "==2.19.0"
    )