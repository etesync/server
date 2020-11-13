import msgpack

from rest_framework.parsers import BaseParser
from rest_framework.exceptions import ParseError


class MessagePackParser(BaseParser):
    media_type = "application/msgpack"

    def parse(self, stream, media_type=None, parser_context=None):
        try:
            return msgpack.unpackb(stream.read(), raw=False)
        except Exception as exc:
            raise ParseError("MessagePack parse error - %s" % str(exc))
