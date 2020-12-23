from fastapi import status


class CustomHttpException(Exception):
    def __init__(self, code: str, detail: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        self.status_code = status_code
        self.code = code
        self.detail = detail

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
