from rest_framework.parsers import FileUploadParser


class ChunkUploadParser(FileUploadParser):
    """
    Parser for chunk upload data.
    """

    def get_filename(self, stream, media_type, parser_context):
        """
        Detects the uploaded file name.
        """
        view = parser_context["view"]
        return parser_context["kwargs"][view.lookup_field]
