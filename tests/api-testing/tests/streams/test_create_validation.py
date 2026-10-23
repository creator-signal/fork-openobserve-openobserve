"""Malformed schema types must remain client errors, including header-unsafe input."""

import os
import uuid

import pytest


@pytest.mark.parametrize(
    "data_type",
    ["\x00", "\x12", "\x7f", "\r\nX-Injected: true", "\u2603", "unknown" * 2048],
)
def test_invalid_type_does_not_corrupt_error_header(create_session, base_url, data_type):
    session = create_session
    org_id = os.environ.get("TEST_ORG_ID", "default")
    stream_name = f"invalid_type_{uuid.uuid4().hex}"
    url = f"{base_url}api/{org_id}/streams/{stream_name}"

    try:
        response = session.post(
            url,
            json={"fields": [{"name": "value", "type": data_type}], "settings": {}},
        )
        assert response.status_code == 400
        assert response.headers["X-Error-Message"] == "invalid data type"
        assert "X-Injected" not in response.headers
        assert response.json()["message"] == f"invalid data type: {data_type}"
        assert session.get(f"{url}/schema").status_code == 404
    finally:
        session.delete(url)
