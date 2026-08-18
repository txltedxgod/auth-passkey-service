import secrets
from typing import Dict, Any

class PasskeyService:
    def create_registration_challenge(self, username: str) -> Dict[str, Any]:
        challenge = secrets.token_urlsafe(32)
        return {
            "challenge": challenge,
            "rp": {"name": "Passkey Security Portal", "id": "localhost"},
            "user": {"id": secrets.token_hex(8), "name": username, "displayName": username}
        }
