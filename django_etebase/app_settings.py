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
from django.utils.functional import cached_property


class AppSettings:
    def __init__(self, prefix):
        self.prefix = prefix

    def import_from_str(self, name):
        from importlib import import_module

        path, prop = name.rsplit('.', 1)

        mod = import_module(path)
        return getattr(mod, prop)

    def _setting(self, name, dflt):
        from django.conf import settings
        return getattr(settings, self.prefix + name, dflt)

    @cached_property
    def API_PERMISSIONS(self):  # pylint: disable=invalid-name
        perms = self._setting("API_PERMISSIONS", ('rest_framework.permissions.IsAuthenticated', ))
        ret = []
        for perm in perms:
            ret.append(self.import_from_str(perm))
        return ret

    @cached_property
    def API_AUTHENTICATORS(self):  # pylint: disable=invalid-name
        perms = self._setting("API_AUTHENTICATORS", ('rest_framework.authentication.TokenAuthentication',
                                                     'rest_framework.authentication.SessionAuthentication'))
        ret = []
        for perm in perms:
            ret.append(self.import_from_str(perm))
        return ret

    @cached_property
    def GET_USER_QUERYSET(self):  # pylint: disable=invalid-name
        get_user_queryset = self._setting("GET_USER_QUERYSET", None)
        if get_user_queryset is not None:
            return self.import_from_str(get_user_queryset)
        return None

    @cached_property
    def CHALLENGE_VALID_SECONDS(self):  # pylint: disable=invalid-name
        return self._setting("CHALLENGE_VALID_SECONDS", 60)


app_settings = AppSettings('ETEBASE_')
