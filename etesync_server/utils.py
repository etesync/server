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

from django.core.management import utils

def get_secret_from_file(path):
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except EnvironmentError:
        with open(path, "w") as f:
            secret_key = utils.get_random_secret_key()
            f.write(secret_key)
            return secret_key
