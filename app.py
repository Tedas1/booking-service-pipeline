"""A tiny, deliberately vulnerable Booking Service.

FOR TEACHING ONLY. Every 'BUG' comment marks a planted weakness used in the
Unit 5 security-testing demo. Never deploy this.

Run it with:  python app.py   (listens on http://127.0.0.1:8080)
"""

from flask import Flask, request, jsonify

from routes import add_route, list_routes
from parser import parse_booking_code

app = Flask(__name__)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/booking/<code>")
def booking(code):
    # Calls the fragile parser; malformed codes crash it (fuzzing demo).
    return jsonify(parse_booking_code(code))


@app.post("/admin/routes")
def admin_add_route():
    """Add or change a gateway route.

    BUG (for the DAST demo): this is an admin action with NO authentication
    and NO authorisation, reachable by anyone who can reach the service. It
    also echoes caller input straight back. A DAST tool reaches it from the
    outside and reports an unauthenticated state-changing endpoint.
    """
    data = request.get_json(force=True)
    rid = add_route(data)
    return jsonify({"added": rid, "echo": data.get("name", "")})


@app.get("/admin/routes")
def admin_list_routes():
    return jsonify(list_routes())


if __name__ == "__main__":
    # BUG: debug=True exposes the Werkzeug debugger (extra SAST finding).
    app.run(host="127.0.0.1", port=8080, debug=True)
