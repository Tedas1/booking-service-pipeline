"""A dependency-free fallback fuzzer for parse_booking_code.

Use this if Atheris is not installed. It feeds random/malformed strings to
the parser and prints the first input that causes an unhandled crash. The
real tool to name in class is Atheris (see fuzz_parser.py); this just makes
the same point with nothing to install.

Run it with:  python fuzz_simple.py
"""

import random
import string

from parser import parse_booking_code

ALPHABET = string.ascii_letters + string.digits + "-" * 5


def random_code(rng):
    n = rng.randint(0, 12)
    return "".join(rng.choice(ALPHABET) for _ in range(n))


def main():
    rng = random.Random(1)  # fixed seed = reproducible in class
    for i in range(1, 100001):
        code = random_code(rng)
        try:
            parse_booking_code(code)
        except Exception as exc:  # noqa: BLE001 - we want to catch anything
            print(f"CRASH after {i} inputs")
            print(f"  input   : {code!r}")
            print(f"  exception: {type(exc).__name__}: {exc}")
            return
    print("No crash found (unexpected for this demo).")


if __name__ == "__main__":
    main()
