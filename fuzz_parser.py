"""Fuzzing harness for parse_booking_code, using Atheris.

Run it with:  python fuzz_parser.py

Atheris generates many inputs and reports any that cause an UNHANDLED
exception. Our parser does not guard its input, so a crash is found quickly.
"""

import sys

import atheris

with atheris.instrument_imports():
    from parser import parse_booking_code


def TestOneInput(data):
    code = data.decode("utf-8", errors="ignore")
    # No try/except on purpose: any exception is a real finding for the demo.
    parse_booking_code(code)


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
