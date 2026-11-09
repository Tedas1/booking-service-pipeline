"""Parsing of booking codes.

Teaching note: parse_booking_code is deliberately fragile so the fuzzing
demo can find inputs that crash it. In a web server an unhandled exception
on user input means a 500 / denial of service.
"""


def parse_booking_code(code):
    """Parse a code of the form 'ROOM-<room>-<nights>'.

    Expected: 'ROOM-12-3'  ->  room 12, 3 nights.
    BUG (for the fuzzing demo): malformed input raises IndexError or
    ValueError, which nothing handles. The fuzzer finds such inputs fast.
    """
    parts = code.split("-")
    room = parts[1]            # IndexError when there is no '-'
    nights = int(parts[2])     # ValueError on non-numeric; IndexError if missing
    return {"room": room, "nights": nights, "total": 100 * nights}
