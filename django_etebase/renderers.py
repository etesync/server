from rest_framework.utils.encoders import JSONEncoder as DRFJSONEncoder
from rest_framework.renderers import JSONRenderer as DRFJSONRenderer

from .serializers import b64encode


class JSONEncoder(DRFJSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes) or isinstance(obj, memoryview):
            return b64encode(obj)
        return super().default(obj)


class JSONRenderer(DRFJSONRenderer):
    """
    Renderer which serializes to JSON with support for our base64
    """
    encoder_class = JSONEncoder
