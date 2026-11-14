"""Options that ``etebase_server.settings`` reads from the ini file."""

import os
import pathlib
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def read_setting(tmp_path, ini, name):
    """Import the settings in a new interpreter with ``ini`` as the config file, and return ``name`` as text."""
    config = tmp_path / "etebase-server.ini"
    config.write_text(ini)
    env = {**os.environ, "ETEBASE_EASY_CONFIG_PATH": str(config), "PYTHONPATH": str(REPO_ROOT)}
    code = f"import etebase_server.settings as s; print(getattr(s, {name!r}, None))"
    result = subprocess.run(
        [sys.executable, "-c", code], env=env, cwd=tmp_path, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def test_max_request_size_is_read_from_the_ini(tmp_path):
    assert read_setting(tmp_path, "[global]\nmax_request_size = 2048\n", "ETEBASE_MAX_REQUEST_SIZE") == "2048"


def test_max_request_size_is_unset_without_the_option(tmp_path):
    assert read_setting(tmp_path, "[global]\n", "ETEBASE_MAX_REQUEST_SIZE") == "None"
