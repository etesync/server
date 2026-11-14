from fastapi import status
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .exceptions import HttpError


class RequestSizeLimitMiddleware:
    """Reject with 413 ``request_too_large`` the HTTP requests whose body is larger than ``max_size`` bytes.

    The body is counted while it is received, so at most ``max_size`` bytes and one more received chunk are read.
    FastAPI reads the body before resolving the dependencies, so the limit applies before authentication.
    """

    def __init__(self, app: ASGIApp, max_size: int):
        self.app = app
        self.max_size = max_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            received += len(message.get("body", b""))
            if received > self.max_size:
                raise HttpError(
                    "request_too_large",
                    f"Request body is larger than {self.max_size} bytes.",
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                )
            return message

        await self.app(scope, limited_receive, send)
