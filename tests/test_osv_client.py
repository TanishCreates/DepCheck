import httpx

from depcheck import osv_client


class FakeResponse:
    def __init__(
        self,
        status_code,
        data=None,
    ):
        self.status_code = status_code
        self._data = data

    def raise_for_status(self):
        if self.status_code >= 400:

            request = httpx.Request(
                "POST",
                osv_client.OSV_QUERY_URL,
            )

            response = httpx.Response(
                self.status_code,
                request=request,
            )

            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=request,
                response=response,
            )

        return self

    def json(self):
        if self._data is None:
            raise ValueError(
                "Invalid JSON"
            )

        return self._data


def test_cache_filename_is_deterministic():
    first = osv_client._cache_filename(
        "requests",
        "2.19.0",
    )

    second = osv_client._cache_filename(
        "requests",
        "2.19.0",
    )

    assert first == second


def test_cache_filename_changes_with_version():
    first = osv_client._cache_filename(
        "requests",
        "2.19.0",
    )

    second = osv_client._cache_filename(
        "requests",
        "2.20.0",
    )

    assert first != second


def test_save_and_load_cache(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        osv_client,
        "CACHE_DIR",
        tmp_path,
    )

    data = {
        "vulns": [
            {
                "id": "TEST-001"
            }
        ]
    }

    osv_client._save_cache(
        "requests",
        "2.19.0",
        data,
    )

    loaded = osv_client._load_cache(
        "requests",
        "2.19.0",
    )

    assert loaded == data


def test_query_package_uses_cache(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        osv_client,
        "CACHE_DIR",
        tmp_path,
    )

    data = {
        "vulns": [
            {
                "id": "TEST-CACHE"
            }
        ]
    }

    osv_client._save_cache(
        "requests",
        "2.19.0",
        data,
    )

    result = osv_client.query_package(
        "requests",
        "2.19.0",
        use_cache=True,
    )

    assert result == data


def test_query_package_success(monkeypatch):

    fake_response = FakeResponse(
        status_code=200,
        data={
            "vulns": [
                {
                    "id": "TEST-001",
                    "summary": (
                        "Test vulnerability"
                    ),
                }
            ]
        },
    )

    def fake_post(*args, **kwargs):
        return fake_response

    monkeypatch.setattr(
        httpx,
        "post",
        fake_post,
    )

    result = osv_client.query_package(
        "example-package",
        "1.0.0",
        use_cache=False,
    )

    assert "vulns" in result

    assert (
        result["vulns"][0]["id"]
        == "TEST-001"
    )


def test_query_package_client_error(
    monkeypatch,
):

    fake_response = FakeResponse(
        status_code=404,
    )

    def fake_post(*args, **kwargs):
        return fake_response

    monkeypatch.setattr(
        httpx,
        "post",
        fake_post,
    )

    result = osv_client.query_package(
        "example-package",
        "1.0.0",
        use_cache=False,
    )

    assert "error" in result

    assert "404" in result["error"]


def test_query_package_network_error(
    monkeypatch,
):

    def fake_post(*args, **kwargs):

        raise httpx.RequestError(
            "Connection failed"
        )

    monkeypatch.setattr(
        httpx,
        "post",
        fake_post,
    )

    # Prevent the test from actually
    # waiting 1 + 2 seconds for retries.
    monkeypatch.setattr(
        osv_client.time,
        "sleep",
        lambda seconds: None,
    )

    result = osv_client.query_package(
        "example-package",
        "1.0.0",
        use_cache=False,
    )

    assert "error" in result

    assert "Connection failed" in result["error"]