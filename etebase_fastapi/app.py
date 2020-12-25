import os

from django.core.wsgi import get_wsgi_application
from fastapi.middleware.cors import CORSMiddleware

from django.conf import settings

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "etebase_server.settings")
application = get_wsgi_application()
from fastapi import FastAPI, Request

from .execptions import CustomHttpException
from .authentication import authentication_router
from .collection import collection_router
from .msgpack import MsgpackResponse

app = FastAPI()
VERSION = "v1"
BASE_PATH = f"/api/{VERSION}"
app.include_router(authentication_router, prefix=f"{BASE_PATH}/authentication")
app.include_router(collection_router, prefix=f"{BASE_PATH}/collection")
if settings.DEBUG:
    from .test_reset_view import test_reset_view_router

    app.include_router(test_reset_view_router, prefix=f"{BASE_PATH}/test/authentication")
app.add_middleware(
    CORSMiddleware, allow_origin_regex="https?://.*", allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
)


@app.exception_handler(CustomHttpException)
async def custom_exception_handler(request: Request, exc: CustomHttpException):
    return MsgpackResponse(status_code=exc.status_code, content=exc.as_dict)
