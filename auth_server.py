from __future__ import annotations

import time
from typing import Dict, Set

from flask import Flask, request, jsonify

from token_utils import generate_token, verify_token, hash_token, check_token


app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    """
    Simple landing endpoint so that hitting http://127.0.0.1:5000/
    in a browser does not return a 404.
    """
    return (
        jsonify(
            {
                "message": "Zero-Trust Auth Server",
                "endpoints": {
                    "health": "/health",
                    "request_token": "/request-token (POST)",
                    "secure_data": "/secure-data (GET, Authorization: Bearer <token>)",
                },
            }
        ),
        200,
    )


# In-memory token store for demo purposes.
# In production, replace this with Redis or a database.
#
# Structure:
#   active_token_hashes[user_id] = {
#       "jti": <last_issued_jti>,
#       "hash": <bcrypt_hash_of_token>,
#       "issued_at": <unix_timestamp>,
#   }
#
#   used_jtis = { "jti1", "jti2", ... }  # for basic replay detection

active_token_hashes: Dict[str, Dict[str, object]] = {}
used_jtis: Set[str] = set()


@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok"}), 200


@app.route("/request-token", methods=["POST"])
def request_token():
    """
    Simulated passwordless "issue me a token" step.

    In a real system this would be triggered after verifying a one-time code,
    WebAuthn assertion, magic link, or OAuth login. Here we focus on the
    token lifecycle and zero-trust checks.
    """
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    token, jti = generate_token(user_id)
    token_hash = hash_token(token)

    active_token_hashes[user_id] = {
        "jti": jti,
        "hash": token_hash,
        "issued_at": int(time.time()),
    }

    # For CSRF-safe usage we expect clients to send this token
    # in the Authorization header as "Bearer <token>".
    return jsonify({"access_token": token, "token_type": "Bearer"}), 201


def _extract_bearer_token() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        return None
    if not auth_header.startswith("Bearer "):
        # Do not accept tokens in other formats or locations to
        # avoid accidentally making cookie-based CSRF vectors.
        return None
    return auth_header.split(" ", 1)[1].strip()


@app.route("/secure-data", methods=["GET"])
def secure_data():
    """
    Protected resource.

    Zero-trust properties:
      - Every request must present a valid, unexpired JWT.
      - We re-verify JWT signature, issuer, audience, expiry each time.
      - We verify the token string against the server-side bcrypt hash.
      - We use the jti claim for basic replay detection (one-time token).
    """
    raw_token = _extract_bearer_token()
    if not raw_token:
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    payload = verify_token(raw_token)
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 401

    user_id = payload.get("sub")
    jti = payload.get("jti")

    if not user_id or not jti:
        return jsonify({"error": "Malformed token"}), 400

    # Basic replay detection: if we've already seen this jti, block it.
    if jti in used_jtis:
        return jsonify({"error": "Token has already been used (replay detected)"}), 403

    record = active_token_hashes.get(user_id)
    if not record:
        return jsonify({"error": "No active token for this user"}), 403

    if record.get("jti") != jti:
        # There is a more recent token for this user; treat old one as invalid.
        return jsonify({"error": "Stale token"}), 403

    if not check_token(raw_token, record.get("hash")):
        return jsonify({"error": "Token mismatch"}), 403

    # Mark this jti as used to prevent replay.
    used_jtis.add(jti)

    # In a stricter model you could also delete active_token_hashes[user_id]
    # here to enforce truly one-time, single-use tokens.

    return jsonify({"data": f"Sensitive data for user {user_id}"}), 200


if __name__ == "__main__":
    # For local dev only; use a real WSGI/ASGI server in production.
    app.run(host="127.0.0.1", port=5000, debug=True)

