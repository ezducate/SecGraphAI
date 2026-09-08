"""Atheris harness for attacker-controlled JSON parsers (run in scheduled CI)."""

from __future__ import annotations

import json
import sys

import atheris

with atheris.instrument_imports():
    from secgraphai.intelligence import parse_nvd
    from secgraphai.targets import discover_openapi


def test_one_input(data: bytes) -> None:
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return
    if not isinstance(document, dict):
        return
    discover_openapi(document)
    parse_nvd(document)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
