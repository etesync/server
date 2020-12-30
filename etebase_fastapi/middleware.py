from starlette.types import ASGIApp, Receive, Scope, Send
from django.db import close_old_connections, reset_queries


class DjangoDbConnectionCleanupMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        reset_queries()
        close_old_connections()
        try:
            await self.app(scope, receive, send)
        finally:
            close_old_connections()
