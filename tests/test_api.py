from fastapi.testclient import TestClient

from depcheck.app import app


client = TestClient(app)


def test_homepage():
    response = client.get("/")

    assert response.status_code == 200
    assert "DepCheck" in response.text


def test_scan_requires_file():
    response = client.post("/scan")

    assert response.status_code == 422


def test_scan_rejects_large_file():
    large_content = b"x" * (
        1024 * 1024 + 1
    )

    response = client.post(
        "/scan",
        files={
            "file": (
                "large.txt",
                large_content,
                "text/plain",
            )
        },
    )

    assert response.status_code == 413
    assert "too large" in response.text.lower()