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

    @property
    def API_PERMISSIONS(self):  # pylint: disable=invalid-name
        perms = self._setting("API_PERMISSIONS", ('rest_framework.permissions.IsAuthenticated', ))
        ret = []
        for perm in perms:
            ret.append(self.import_from_str(perm))
        return ret

    @property
    def API_AUTHENTICATORS(self):  # pylint: disable=invalid-name
        perms = self._setting("API_AUTHENTICATORS", ('rest_framework.authentication.TokenAuthentication',
                                                     'rest_framework.authentication.SessionAuthentication'))
        ret = []
        for perm in perms:
            ret.append(self.import_from_str(perm))
        return ret


app_settings = AppSettings('ETESYNC_')
