from pathlib import Path

from depcheck.parsers import (
    parse_pyproject,
    parse_pipfile,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_dependency_file,
)


BASE_DIR = (
    Path(__file__).parent
    / "sample_files"
    / "python_formats"
)


def test_parse_pyproject():
    path = BASE_DIR / "pyproject.toml"

    dependencies, skipped = parse_pyproject(path)

    names = {
        item["name"]
        for item in dependencies
    }

    assert "requests" in names
    assert "django" in names
    assert "pytest" in names

    assert len(dependencies) == 3

    skipped_text = [
        item.text
        for item in skipped
    ]

    assert "flask>=1.0" in skipped_text


def test_parse_pipfile():
    path = BASE_DIR / "Pipfile"

    dependencies, skipped = parse_pipfile(path)

    names = {
        item["name"]
        for item in dependencies
    }

    assert "requests" in names
    assert "django" in names
    assert "pytest" in names

    assert len(dependencies) == 3

    skipped_text = [
        item.text
        for item in skipped
    ]

    assert "flask>=1.0" in skipped_text


def test_parse_pipfile_lock():
    path = BASE_DIR / "Pipfile.lock"

    dependencies, skipped = parse_pipfile_lock(path)

    versions = {
        item["name"]: item["version"]
        for item in dependencies
    }

    assert versions["requests"] == "2.19.0"
    assert versions["django"] == "2.2.0"
    assert versions["pytest"] == "7.4.0"

    assert len(dependencies) == 3
    assert skipped == []


def test_parse_poetry_lock():
    path = BASE_DIR / "poetry.lock"

    dependencies, skipped = parse_poetry_lock(path)

    versions = {
        item["name"]: item["version"]
        for item in dependencies
    }

    assert versions["requests"] == "2.19.0"
    assert versions["django"] == "2.2.0"
    assert versions["pytest"] == "7.4.0"

    assert len(dependencies) == 3
    assert skipped == []


def test_automatic_dependency_file_detection():
    test_cases = {
        "requirements.txt": "requirements.txt",
        "pyproject.toml": "pyproject.toml",
        "Pipfile": "Pipfile",
        "Pipfile.lock": "Pipfile.lock",
        "poetry.lock": "poetry.lock",
    }

    for filename, expected_filename in test_cases.items():

        if filename == "requirements.txt":
            continue

        path = BASE_DIR / expected_filename

        dependencies, skipped = (
            parse_dependency_file(path)
        )

        assert dependencies