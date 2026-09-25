import httpx


OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def query_package(name, version):
    """
    Ask OSV.dev whether one exact package version
    has known vulnerabilities.
    """

    payload = {
        "package": {
            "ecosystem": "PyPI",
            "name": name,
        },
        "version": version,
    }

    response = httpx.post(
        OSV_QUERY_URL,
        json=payload,
        timeout=30.0,
    )

    response.raise_for_status()

    return response.json()