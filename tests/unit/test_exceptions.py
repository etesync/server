"""Pure unit tests for ``etebase_server.fastapi.exceptions``.

They cover the HTTP exception hierarchy and the error-transformation helpers. These are
"classic" unit tests: they need no database, no configured Django settings, and no running
server. The only requirement is that ``django.core.exceptions``, ``fastapi`` and ``pydantic``
are importable.
"""

import pytest
from django.core.exceptions import ValidationError as DjangoValidationError
from fastapi import HTTPException, status

from etebase_server.fastapi.exceptions import (
    AuthenticationFailed,
    CustomHttpException,
    HttpError,
    NotAuthenticated,
    NotSupported,
    PermissionDenied,
    ValidationError,
    flatten_errors,
    transform_validation_error,
)


class TestCustomHttpException:
    def test_defaults(self):
        exc = CustomHttpException(code="boom", detail="Something broke")
        assert exc.code == "boom"
        assert exc.detail == "Something broke"
        assert exc.status_code == status.HTTP_400_BAD_REQUEST
        assert isinstance(exc, HTTPException)

    def test_custom_status_code(self):
        exc = CustomHttpException(code="teapot", detail="no coffee", status_code=status.HTTP_418_IM_A_TEAPOT)
        assert exc.status_code == status.HTTP_418_IM_A_TEAPOT

    def test_as_dict(self):
        exc = CustomHttpException(code="boom", detail="broke")
        assert exc.as_dict == {"code": "boom", "detail": "broke"}


@pytest.mark.parametrize(
    "exc_cls, expected_code, expected_status",
    [
        (AuthenticationFailed, "authentication_failed", status.HTTP_401_UNAUTHORIZED),
        (NotAuthenticated, "not_authenticated", status.HTTP_401_UNAUTHORIZED),
        (PermissionDenied, "permission_denied", status.HTTP_403_FORBIDDEN),
        (NotSupported, "not_implemented", status.HTTP_501_NOT_IMPLEMENTED),
    ],
)
def test_subclass_defaults(exc_cls, expected_code, expected_status):
    exc = exc_cls()
    assert exc.code == expected_code
    assert exc.status_code == expected_status
    assert isinstance(exc, CustomHttpException)


class TestHttpError:
    def test_defaults(self):
        exc = HttpError(code="bad", detail="nope")
        assert exc.code == "bad"
        assert exc.status_code == status.HTTP_400_BAD_REQUEST
        assert exc.errors is None

    def test_empty_code_falls_back_to_generic(self):
        exc = HttpError(code="", detail="nope")
        assert exc.code == "generic_error"

    def test_as_dict_without_errors(self):
        exc = HttpError(code="bad", detail="nope")
        assert exc.as_dict == {"code": "bad", "detail": "nope", "errors": None}

    def test_as_dict_serializes_nested_validation_errors(self):
        nested = ValidationError(code="invalid", detail="too short", field="password")
        exc = HttpError(code="field_errors", detail="Field validations failed.", errors=[nested])
        result = exc.as_dict
        assert result["code"] == "field_errors"
        assert result["detail"] == "Field validations failed."
        assert result["errors"] == [{"field": "password", "code": "invalid", "detail": "too short"}]


class TestValidationError:
    def test_field_is_stored(self):
        exc = ValidationError(code="invalid", detail="bad value", field="email")
        assert exc.field == "email"
        assert exc.code == "invalid"
        assert isinstance(exc, HttpError)


class TestTransformValidationError:
    def test_dict_errors_become_field_errors(self):
        django_err = DjangoValidationError({"name": ["This field is required."]})
        with pytest.raises(HttpError) as exc_info:
            transform_validation_error("user", django_err)

        exc = exc_info.value
        assert exc.code == "field_errors"
        assert exc.detail == "Field validations failed."
        assert len(exc.errors) == 1
        only = exc.errors[0]
        assert isinstance(only, ValidationError)
        assert only.field == "user.name"
        assert only.detail == "This field is required."

    def test_list_errors_become_field_errors(self):
        django_err = DjangoValidationError(["first problem", "second problem"])
        with pytest.raises(HttpError) as exc_info:
            transform_validation_error("user", django_err)

        exc = exc_info.value
        assert exc.code == "field_errors"
        assert len(exc.errors) == 2

    def test_single_message_raises_plain_http_error(self):
        django_err = DjangoValidationError("just one message", code="custom_code")
        with pytest.raises(HttpError) as exc_info:
            transform_validation_error("user", django_err)

        exc = exc_info.value
        assert exc.code == "custom_code"
        assert exc.detail == "just one message"


class TestFlattenErrors:
    def test_flattens_list_of_django_errors(self):
        django_err = DjangoValidationError(["problem a", "problem b"])
        result = flatten_errors("field", django_err.error_list)
        assert len(result) == 2
        assert all(isinstance(e, ValidationError) for e in result)
        assert all(e.field == "field" for e in result)
        assert {e.detail for e in result} == {"problem a", "problem b"}

    def test_flattens_nested_dict_of_django_errors(self):
        django_err = DjangoValidationError({"name": ["required"], "email": ["invalid"]})
        result = flatten_errors("user", django_err.error_dict)
        assert len(result) == 2
        fields = {e.field for e in result}
        assert fields == {"user.name", "user.email"}
