import hashlib
import json
import time
from pathlib import Path

import httpx


OSV_QUERY_URL = "https://api.osv.dev/v1/query"

CACHE_DIR = Path(".depcheck_cache")
CACHE_DIR.mkdir(exist_ok=True)

MAX_RETRIES = 3
TIMEOUT = 30.0


def _cache_filename(name, version):
    key = hashlib.sha256(
        f"{name.lower()}@{version}".encode("utf-8")
    ).hexdigest()

    return CACHE_DIR / f"{key}.json"


def _load_cache(name, version):
    path = _cache_filename(name, version)

    if not path.exists():
        return None

    try:
        return json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

    except (
        OSError,
        json.JSONDecodeError,
    ):
        return None


def _save_cache(name, version, data):
    path = _cache_filename(
        name,
        version,
    )

    try:
        path.write_text(
            json.dumps(
                data,
                indent=2,
            ),
            encoding="utf-8",
        )

    except OSError:
        pass


def query_package(
    name,
    version,
    use_cache=True,
):
    """
    Query OSV.dev for one exact package version.

    Includes:
    - local caching
    - retries
    - timeout handling
    - graceful network errors
    """

    if use_cache:

        cached_data = _load_cache(
            name,
            version,
        )

        if cached_data is not None:

            print(
                f"[CACHE] {name}=={version}"
            )

            return cached_data

    payload = {
        "package": {
            "ecosystem": "PyPI",
            "name": name,
        },
        "version": version,
    }

    last_error = None

    for attempt in range(
        1,
        MAX_RETRIES + 1,
    ):

        try:

            print(
                f"[OSV] Checking "
                f"{name}=={version} "
                f"(attempt {attempt}/{MAX_RETRIES})"
            )

            response = httpx.post(
                OSV_QUERY_URL,
                json=payload,
                timeout=TIMEOUT,
            )

            # Handle HTTP errors.
            response.raise_for_status()

            # Parse JSON safely.
            try:
                data = response.json()

            except ValueError as exc:

                last_error = (
                    f"Invalid JSON from OSV.dev: "
                    f"{exc}"
                )

                break

            _save_cache(
                name,
                version,
                data,
            )

            return data

        except httpx.HTTPStatusError as exc:

            status_code = (
                exc.response.status_code
            )

            # Client-side errors such as
            # 400, 404, etc. don't need retries.
            if 400 <= status_code < 500:

                return {
                    "error": (
                        "OSV.dev returned "
                        f"HTTP {status_code}"
                    )
                }

            last_error = (
                f"OSV.dev returned "
                f"HTTP {status_code}"
            )

        except (
            httpx.RequestError,
            httpx.TimeoutException,
        ) as exc:

            last_error = str(exc)

        except Exception as exc:

            last_error = str(exc)

        if attempt < MAX_RETRIES:

            time.sleep(
                2 ** (attempt - 1)
            )

    return {
        "error": (
            last_error
            or "Unable to query OSV.dev."
        )
    }


def query_packages(
    packages,
    use_cache=True,
):
    results = {}

    for package in packages:

        name = package["name"]
        version = package["version"]

        results[
            f"{name}=={version}"
        ] = query_package(
            name,
            version,
            use_cache=use_cache,
        )

    return results