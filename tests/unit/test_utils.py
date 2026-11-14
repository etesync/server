"""Pure unit tests for ``etebase_server.utils.get_secret_from_file``.

They verify reading, generation and permissions of the file holding the ``SECRET_KEY``.
They use only pytest's ``tmp_path`` fixture: no database, settings or server.
"""

import os
import stat

from etebase_server.utils import get_secret_from_file


def test_reads_existing_secret_stripped(tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("  s3cr3t-value\n")

    assert get_secret_from_file(str(secret_file)) == "s3cr3t-value"


def test_creates_secret_when_missing(tmp_path):
    secret_file = tmp_path / "missing.txt"
    assert not secret_file.exists()

    secret = get_secret_from_file(str(secret_file))

    assert secret  # non-empty
    assert len(secret) >= 32
    assert secret_file.exists()
    # The file must contain exactly the returned secret.
    assert secret_file.read_text() == secret


def test_created_secret_file_is_private(tmp_path):
    secret_file = tmp_path / "perms.txt"

    get_secret_from_file(str(secret_file))

    mode = stat.S_IMODE(os.stat(str(secret_file)).st_mode)
    assert mode == 0o600


def test_is_stable_across_calls(tmp_path):
    secret_file = tmp_path / "stable.txt"

    first = get_secret_from_file(str(secret_file))
    second = get_secret_from_file(str(secret_file))

    assert first == second
