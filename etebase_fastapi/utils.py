from fastapi import status

from django.db.models import QuerySet
from django.core.exceptions import ObjectDoesNotExist

from .exceptions import ValidationError


def get_object_or_404(queryset: QuerySet, **kwargs):
    try:
        return queryset.get(**kwargs)
    except ObjectDoesNotExist as e:
        raise ValidationError("does_not_exist", str(e), status_code=status.HTTP_404_NOT_FOUND)
