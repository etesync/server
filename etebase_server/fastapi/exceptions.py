import typing as t

from django.core.exceptions import ValidationError as DjangoValidationError
from fastapi import HTTPException, status
from pydantic import BaseModel


class HttpErrorField(BaseModel):
    field: str
    code: str
    detail: str

    class Config:
        orm_mode = True


class HttpErrorOut(BaseModel):
    code: str
    detail: str
    errors: t.Optional[t.List[HttpErrorField]]

    class Config:
        orm_mode = True


class CustomHttpException(HTTPException):
    def __init__(self, code: str, detail: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        self.code = code
        super().__init__(status_code, detail)

    @property
    def as_dict(self) -> dict:
        return {"code": self.code, "detail": self.detail}


class AuthenticationFailed(CustomHttpException):
    def __init__(
        self,
        code="authentication_failed",
        detail: str = "Incorrect authentication credentials.",
        status_code: int = status.HTTP_401_UNAUTHORIZED,
    ):
        super().__init__(code=code, detail=detail, status_code=status_code)


class NotAuthenticated(CustomHttpException):
    def __init__(
        self,
        code="not_authenticated",
        detail: str = "Authentication credentials were not provided.",
        status_code: int = status.HTTP_401_UNAUTHORIZED,
    ):
        super().__init__(code=code, detail=detail, status_code=status_code)


class PermissionDenied(CustomHttpException):
    def __init__(
        self,
        code="permission_denied",
        detail: str = "You do not have permission to perform this action.",
        status_code: int = status.HTTP_403_FORBIDDEN,
    ):
        super().__init__(code=code, detail=detail, status_code=status_code)


class NotSupported(CustomHttpException):
    def __init__(
        self,
        code="not_implemented",
        detail: str = "This server's configuration does not support this request.",
        status_code: int = status.HTTP_501_NOT_IMPLEMENTED,
    ):
        super().__init__(code=code, detail=detail, status_code=status_code)


class HttpError(CustomHttpException):
    def __init__(
        self,
        code: str,
        detail: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        errors: t.Optional[t.List["HttpError"]] = None,
    ):
        self.errors = errors
        super().__init__(code=code or "generic_error", detail=detail, status_code=status_code)

    @property
    def as_dict(self) -> dict:
        return HttpErrorOut(code=self.code, errors=self.errors, detail=self.detail).dict()


class ValidationError(HttpError):
    def __init__(
        self,
        code: str,
        detail: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        errors: t.Optional[t.List["HttpError"]] = None,
        field: t.Optional[str] = None,
    ):
        self.field = field
        super().__init__(code=code, detail=detail, errors=errors, status_code=status_code)


def flatten_errors(field_name: str, errors) -> t.List[HttpError]:
    ret: t.List[HttpError] = []
    if isinstance(errors, dict):
        for error_key in errors:
            error = errors[error_key]
            ret.extend(flatten_errors("{}.{}".format(field_name, error_key), error))
    else:
        for error in errors:
            if error.messages:
                message = error.messages[0]
            else:
                message = str(error)
            ret.append(ValidationError(code=error.code or "validation_error", detail=message, field=field_name))
    return ret


def transform_validation_error(prefix: str, err: DjangoValidationError):
    if hasattr(err, "error_dict"):
        errors = flatten_errors(prefix, err.error_dict)
    elif not hasattr(err, "message"):
        errors = flatten_errors(prefix, err.error_list)
    else:
        raise HttpError(err.code or "validation_error", err.message)
    raise HttpError(code="field_errors", detail="Field validations failed.", errors=errors)
