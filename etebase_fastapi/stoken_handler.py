import typing as t

from django.db.models import QuerySet
from fastapi import status

from django_etebase.exceptions import EtebaseValidationError
from django_etebase.models import Stoken

# TODO missing stoken_annotation type
StokenAnnotation = t.Any


def get_stoken_obj(stoken: t.Optional[str]):
    if stoken is not None:
        try:
            return Stoken.objects.get(uid=stoken)
        except Stoken.DoesNotExist:
            raise EtebaseValidationError("bad_stoken", "Invalid stoken.", status_code=status.HTTP_400_BAD_REQUEST)

    return None


def filter_by_stoken(
    stoken: t.Optional[str], queryset: QuerySet, stoken_annotation: StokenAnnotation
) -> t.Tuple[QuerySet, t.Optional[str]]:
    stoken_rev = get_stoken_obj(stoken)

    queryset = queryset.annotate(max_stoken=stoken_annotation).order_by("max_stoken")

    if stoken_rev is not None:
        queryset = queryset.filter(max_stoken__gt=stoken_rev.id)

    return queryset, stoken_rev


def get_queryset_stoken(queryset: list) -> t.Optional[Stoken]:
    maxid = -1
    for row in queryset:
        rowmaxid = getattr(row, "max_stoken") or -1
        maxid = max(maxid, rowmaxid)
    new_stoken = (maxid >= 0) and Stoken.objects.get(id=maxid)

    return new_stoken or None


def filter_by_stoken_and_limit(
    stoken: t.Optional[str], limit: int, queryset: QuerySet, stoken_annotation: StokenAnnotation
) -> t.Tuple[list, t.Optional[Stoken], bool]:

    queryset, stoken_rev = filter_by_stoken(stoken=stoken, queryset=queryset, stoken_annotation=stoken_annotation)

    result = list(queryset[: limit + 1])
    if len(result) < limit + 1:
        done = True
    else:
        done = False
        result = result[:-1]

    new_stoken_obj = get_queryset_stoken(result) or stoken_rev

    return result, new_stoken_obj, done
