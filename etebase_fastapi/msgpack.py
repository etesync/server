import typing as t
import msgpack
from fastapi.routing import APIRoute, get_request_handler
from starlette.requests import Request
from starlette.responses import Response


class MsgpackRequest(Request):
    media_type = "application/msgpack"

    async def json(self) -> bytes:
        if not hasattr(self, "_json"):
            body = await super().body()
            self._json = msgpack.unpackb(body, raw=False)
        return self._json


class MsgpackResponse(Response):
    media_type = "application/msgpack"

    def render(self, content: t.Any) -> bytes:
        return msgpack.packb(content, use_bin_type=True)


class MsgpackRoute(APIRoute):
    # keep track of content-type -> request classes
    REQUESTS_CLASSES = {MsgpackRequest.media_type: MsgpackRequest}
    # keep track of content-type -> response classes
    ROUTES_HANDLERS_CLASSES = {MsgpackResponse.media_type: MsgpackResponse}

    def _get_media_type_route_handler(self, media_type):
        return get_request_handler(
            dependant=self.dependant,
            body_field=self.body_field,
            status_code=self.status_code,
            # use custom response class or fallback on default self.response_class
            response_class=self.ROUTES_HANDLERS_CLASSES.get(media_type, self.response_class),
            response_field=self.secure_cloned_response_field,
            response_model_include=self.response_model_include,
            response_model_exclude=self.response_model_exclude,
            response_model_by_alias=self.response_model_by_alias,
            response_model_exclude_unset=self.response_model_exclude_unset,
            response_model_exclude_defaults=self.response_model_exclude_defaults,
            response_model_exclude_none=self.response_model_exclude_none,
            dependency_overrides_provider=self.dependency_overrides_provider,
        )

    def get_route_handler(self) -> t.Callable:
        async def custom_route_handler(request: Request) -> Response:

            content_type = request.headers.get("Content-Type")
            try:
                request_cls = self.REQUESTS_CLASSES[content_type]
                request = request_cls(request.scope, request.receive)
            except KeyError:
                # nothing registered to handle content_type, process given requests as-is
                pass

            accept = request.headers.get("Accept")
            route_handler = self._get_media_type_route_handler(accept)
            return await route_handler(request)

        return custom_route_handler
