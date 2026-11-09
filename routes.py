"""In-memory route table for the Booking Service gateway.

Teaching note: this module contains ONE deliberate vulnerability for the
SAST demo. Do not copy this pattern into real code.
"""

ROUTES = {}


def add_route(data):
    """Add a routing rule from a caller-supplied definition.

    The 'filter.value' field is meant to be a small setting (e.g. a number).
    BUG (for the SAST demo): the value is passed to eval(), so a caller can
    send code instead of data and have it executed. This is the Python
    equivalent of the Spring SpEL injection from Unit 4 (CWE-95 / CWE-917).
    """
    name = data["name"]
    value = data["filter"]["value"]
    result = eval(value)  # <-- Bandit flags this (B307, use of eval)
    ROUTES[name] = result
    return name


def list_routes():
    return dict(ROUTES)
