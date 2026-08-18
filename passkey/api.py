from fastapi import FastAPI
from passkey.service import PasskeyService

app = FastAPI(title="WebAuthn Passkey Service", version="0.1.0")
svc = PasskeyService()

@app.post("/api/v1/auth/register-challenge")
def challenge(username: str):
    return svc.create_registration_challenge(username)
