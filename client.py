import json

import requests


SERVER = "http://127.0.0.1:5000"


def pretty(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True)


def main() -> None:
    # In a real system this user_id would be the result of a prior
    # passwordless verification (e.g., WebAuthn, OTP, magic link).
    user_id = "user123"

    print(f"Requesting access token for user_id={user_id!r} ...")
    res = requests.post(f"{SERVER}/request-token", json={"user_id": user_id}, timeout=5)
    res.raise_for_status()

    body = res.json()
    access_token = body["access_token"]
    token_type = body.get("token_type", "Bearer")

    print("\nReceived token response:")
    print(pretty(body))

    headers = {"Authorization": f"{token_type} {access_token}"}

    print("\nCalling /secure-data with Authorization header ...")
    secure_res = requests.get(f"{SERVER}/secure-data", headers=headers, timeout=5)
    print(f"Status: {secure_res.status_code}")
    print("Response JSON:")
    print(pretty(secure_res.json()))

    # Demonstrate replay protection by calling again with the same token.
    print("\nReplaying the same token (should be rejected as replay) ...")
    replay_res = requests.get(f"{SERVER}/secure-data", headers=headers, timeout=5)
    print(f"Status: {replay_res.status_code}")
    print("Response JSON:")
    print(pretty(replay_res.json()))


if __name__ == "__main__":
    main()
