# Copyright © 2017 Tom Hacohen
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, version 3.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
import typing as t

from django.utils.functional import cached_property


class AppSettings:
    def __init__(self, prefix):
        self.prefix = prefix

    def import_from_str(self, name):
        from importlib import import_module

        path, prop = name.rsplit(".", 1)

        mod = import_module(path)
        return getattr(mod, prop)

    def _setting(self, name, dflt):
        from django.conf import settings

        return getattr(settings, self.prefix + name, dflt)

    @cached_property
    def REDIS_URI(self) -> t.Optional[str]:  # noqa: N802
        return self._setting("REDIS_URI", None)

    @cached_property
    def API_PERMISSIONS_READ(self):  # noqa: N802
        perms = self._setting("API_PERMISSIONS_READ", tuple())
        ret = []
        for perm in perms:
            ret.append(self.import_from_str(perm))
        return ret

    @cached_property
    def API_PERMISSIONS_WRITE(self):  # noqa: N802
        perms = self._setting("API_PERMISSIONS_WRITE", tuple())
        ret = []
        for perm in perms:
            ret.append(self.import_from_str(perm))
        return ret

    @cached_property
    def GET_USER_QUERYSET_FUNC(self):  # noqa: N802
        get_user_queryset = self._setting("GET_USER_QUERYSET_FUNC", None)
        if get_user_queryset is not None:
            return self.import_from_str(get_user_queryset)
        return None

    @cached_property
    def CREATE_USER_FUNC(self):  # noqa: N802
        func = self._setting("CREATE_USER_FUNC", None)
        if func is not None:
            return self.import_from_str(func)
        return None

    @cached_property
    def DASHBOARD_URL_FUNC(self):  # noqa: N802
        func = self._setting("DASHBOARD_URL_FUNC", None)
        if func is not None:
            return self.import_from_str(func)
        return None

    @cached_property
    def CHUNK_PATH_FUNC(self):  # noqa: N802
        func = self._setting("CHUNK_PATH_FUNC", None)
        if func is not None:
            return self.import_from_str(func)
        return None

    @cached_property
    def CHALLENGE_VALID_SECONDS(self):  # noqa: N802
        return self._setting("CHALLENGE_VALID_SECONDS", 60)


app_settings = AppSettings("ETEBASE_")
