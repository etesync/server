#!/usr/bin/env bash

set -ex

mypy .
npx -q pyright@1.1.172 .
ruff check .
ruff format --check .
