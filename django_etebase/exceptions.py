from rest_framework import serializers, status


class EtebaseValidationError(serializers.ValidationError):
    def __init__(self, code, detail, status_code=status.HTTP_400_BAD_REQUEST):
        super().__init__(
            {"code": code, "detail": detail,}
        )
        self.status_code = status_code
