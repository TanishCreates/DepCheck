from pathlib import Path
import json
import re
import tomllib

from packaging.requirements import Requirement

from depcheck.models import SkippedRequirement


def make_skipped(line, text, reason):
    return SkippedRequirement(
        line=line,
        text=text,
        reason=reason,
    )


def parse_requirement_line(
    line: str,
    line_number: int,
):
    """
    Parse one Python dependency requirement.
    """

    text = line.strip()

    if not text:
        return None

    if text.startswith("#"):
        return None

    if text.startswith(("-r ", "--requirement ")):
        return None

    if text.startswith(("-e ", "--editable ")):
        return None

    try:
        requirement = Requirement(text)

    except Exception:
        return None

    specifier = str(
        requirement.specifier
    )

    match = re.fullmatch(
        r"==\s*([0-9][^,;\s]*)",
        specifier,
    )

    if not match:
        return None

    version = match.group(1)

    return {
        "name": requirement.name,
        "version": version,
        "requirement": text,
        "version_specifier": specifier,
    }


def parse_requirements(path):
    """
    Parse requirements.txt.
    """

    dependencies = []
    skipped = []

    content = Path(path).read_text(
        encoding="utf-8"
    )

    for line_number, line in enumerate(
        content.splitlines(),
        start=1,
    ):
        text = line.strip()

        if not text or text.startswith("#"):
            continue

        result = parse_requirement_line(
            text,
            line_number,
        )

        if result is None:
            skipped.append(
                make_skipped(
                    line_number,
                    text,
                    "Requirement does not contain an exact version.",
                )
            )
            continue

        dependencies.append(result)

    return dependencies, skipped


def _parse_dependency_string(value):
    """
    Parse a dependency string such as:

        requests==2.31.0
    """

    if not isinstance(value, str):
        return None

    value = value.strip()

    if not value:
        return None

    try:
        requirement = Requirement(value)

    except Exception:
        return None

    specifier = str(
        requirement.specifier
    )

    match = re.fullmatch(
        r"==\s*([0-9][^,;\s]*)",
        specifier,
    )

    if not match:
        return None

    return {
        "name": requirement.name,
        "version": match.group(1),
        "requirement": value,
        "version_specifier": specifier,
    }


def parse_pyproject(path):
    """
    Parse dependencies from pyproject.toml.
    """

    dependencies = []
    skipped = []

    path = Path(path)

    try:
        data = tomllib.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

    except Exception as exc:
        return [], [
            make_skipped(
                0,
                str(path),
                f"Invalid TOML file: {exc}",
            )
        ]

    project = data.get(
        "project",
        {},
    )

    dependency_groups = [
        project.get(
            "dependencies",
            [],
        )
    ]

    optional_dependencies = project.get(
        "optional-dependencies",
        {},
    )

    if isinstance(
        optional_dependencies,
        dict,
    ):
        dependency_groups.extend(
            optional_dependencies.values()
        )

    for group in dependency_groups:

        if not isinstance(
            group,
            list,
        ):
            continue

        for value in group:

            result = _parse_dependency_string(
                value
            )

            if result is None:

                skipped.append(
                    make_skipped(
                        0,
                        str(value),
                        "Dependency does not contain an exact version.",
                    )
                )

                continue

            dependencies.append(result)

    return dependencies, skipped


def parse_pipfile(path):
    """
    Parse dependencies from Pipfile.
    """

    dependencies = []
    skipped = []

    path = Path(path)

    try:
        data = tomllib.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

    except Exception as exc:
        return [], [
            make_skipped(
                0,
                str(path),
                f"Invalid TOML file: {exc}",
            )
        ]

    for section_name in (
        "packages",
        "dev-packages",
    ):

        packages = data.get(
            section_name,
            {},
        )

        if not isinstance(
            packages,
            dict,
        ):
            continue

        for name, value in packages.items():

            if isinstance(value, str):

                requirement = (
                    f"{name}{value}"
                )

            elif isinstance(value, dict):

                version = value.get(
                    "version"
                )

                if not version:
                    skipped.append(
                        make_skipped(
                            0,
                            str(name),
                            "Pipfile dependency does not contain an exact version.",
                        )
                    )
                    continue

                requirement = (
                    f"{name}{version}"
                )

            else:
                skipped.append(
                    make_skipped(
                        0,
                        str(name),
                        "Unsupported Pipfile dependency format.",
                    )
                )
                continue

            result = _parse_dependency_string(
                requirement
            )

            if result is None:
                skipped.append(
                    make_skipped(
                        0,
                        requirement,
                        "Dependency does not contain an exact version.",
                    )
                )
                continue

            dependencies.append(result)

    return dependencies, skipped


def parse_pipfile_lock(path):
    """
    Parse exact package versions from Pipfile.lock.
    """

    dependencies = []
    skipped = []

    path = Path(path)

    try:
        data = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

    except Exception as exc:
        return [], [
            make_skipped(
                0,
                str(path),
                f"Invalid JSON file: {exc}",
            )
        ]

    for section_name in (
        "default",
        "develop",
    ):

        packages = data.get(
            section_name,
            {},
        )

        if not isinstance(
            packages,
            dict,
        ):
            continue

        for name, info in packages.items():

            if not isinstance(
                info,
                dict,
            ):
                continue

            version = info.get(
                "version"
            )

            if not version:
                skipped.append(
                    make_skipped(
                        0,
                        str(name),
                        "Lock file entry has no version.",
                    )
                )
                continue

            version = str(
                version
            ).lstrip("=")

            dependencies.append(
                {
                    "name": name,
                    "version": version,
                    "requirement": (
                        f"{name}=={version}"
                    ),
                    "version_specifier": (
                        f"=={version}"
                    ),
                }
            )

    return dependencies, skipped


def parse_poetry_lock(path):
    """
    Parse exact package versions from poetry.lock.
    """

    dependencies = []
    skipped = []

    path = Path(path)

    try:
        data = tomllib.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

    except Exception as exc:
        return [], [
            make_skipped(
                0,
                str(path),
                f"Invalid TOML file: {exc}",
            )
        ]

    packages = data.get(
        "package",
        [],
    )

    if not isinstance(
        packages,
        list,
    ):
        return dependencies, skipped

    for package in packages:

        if not isinstance(
            package,
            dict,
        ):
            continue

        name = package.get(
            "name"
        )

        version = package.get(
            "version"
        )

        if not name or not version:

            skipped.append(
                make_skipped(
                    0,
                    str(package),
                    "Poetry lock entry is missing name or version.",
                )
            )

            continue

        dependencies.append(
            {
                "name": name,
                "version": version,
                "requirement": (
                    f"{name}=={version}"
                ),
                "version_specifier": (
                    f"=={version}"
                ),
            }
        )

    return dependencies, skipped


def parse_dependency_file(path):
    """
    Automatically select the correct parser
    based on the dependency file name.
    """

    path = Path(path)

    filename = path.name.lower()

    if filename.endswith(".txt"):
        return parse_requirements(path)

    if filename == "pyproject.toml":
        return parse_pyproject(path)

    if filename == "pipfile":
        return parse_pipfile(path)

    if filename == "pipfile.lock":
        return parse_pipfile_lock(path)

    if filename == "poetry.lock":
        return parse_poetry_lock(path)

    return [], [
        make_skipped(
            0,
            filename,
            "Unsupported dependency file format.",
        )
    ]