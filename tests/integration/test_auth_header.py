"""A malformed Authorization header is rejected as unauthenticated instead of failing with a 500."""

import pytest


@pytest.mark.parametrize("token", ["", "with spaces"], ids=["no credentials", "extra parts"])
def test_malformed_authorization_header_is_rejected(api_request, token):
    status, body = api_request("GET", "/api/v1/collection/", token=token)

    assert status == 401
    assert body["code"] == "authentication_failed"
