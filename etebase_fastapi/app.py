import os

from django.core.wsgi import get_wsgi_application
from fastapi.middleware.cors import CORSMiddleware

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "etebase_server.settings")
application = get_wsgi_application()
from fastapi import FastAPI, Request

from .execptions import CustomHttpException
from .authentication import authentication_router
from .msgpack import MsgpackResponse

app = FastAPI()
app.include_router(authentication_router, prefix="/api/v1/authentication")
app.add_middleware(
    CORSMiddleware, allow_origin_regex="https?://.*", allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
)


@app.exception_handler(CustomHttpException)
async def custom_exception_handler(request: Request, exc: CustomHttpException):
    return MsgpackResponse(status_code=exc.status_code, content=exc.as_dict)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
