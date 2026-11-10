"""FastAPI HTTP endpoints for WebAuthn / FIDO2 passkey registration and authentication."""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from passkey.schemas import (
    AuthenticationReceipt,
    CredentialSummary,
    LoginBeginRequest,
    LoginFinishRequest,
    RegisterBeginRequest,
    RegisterFinishRequest,
    RegistrationReceipt,
)
from passkey.service import PasskeyError, PasskeyService

app = FastAPI(title="WebAuthn Passkey Service", version="1.0.0")
svc = PasskeyService()


@app.exception_handler(PasskeyError)
async def passkey_error_handler(_request: Request, exc: PasskeyError) -> JSONResponse:
    """Return consistent JSON error responses for domain WebAuthn failures."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.__class__.__name__, "detail": exc.detail},
    )


@app.get("/health", tags=["Monitoring"])
def health_check() -> dict[str, str]:
    """Liveness check endpoint."""
    return {"status": "healthy", "rp_id": svc.rp_id}


@app.post("/api/v1/auth/register-challenge", tags=["Registration"])
def challenge(username: str) -> dict[str, object]:
    """Legacy-compatible endpoint to create a WebAuthn registration challenge."""
    return svc.create_registration_challenge(username)


@app.post("/api/v1/auth/register/begin", tags=["Registration"])
def register_begin(payload: RegisterBeginRequest) -> dict[str, object]:
    """Start passkey registration by issuing PublicKeyCredentialCreationOptions."""
    return svc.create_registration_challenge(
        username=payload.username,
        display_name=payload.display_name,
        require_user_verification=payload.require_user_verification,
    )


@app.post(
    "/api/v1/auth/register/finish",
    response_model=RegistrationReceipt,
    status_code=status.HTTP_201_CREATED,
    tags=["Registration"],
)
def register_finish(payload: RegisterFinishRequest) -> RegistrationReceipt:
    """Complete registration by verifying attestation and enrolling credential key."""
    return svc.complete_registration(
        username=payload.username,
        challenge=payload.challenge,
        client_data_b64=payload.client_data_b64,
        attestation_object_b64=payload.attestation_object_b64,
        device_name=payload.device_name,
    )


@app.post("/api/v1/auth/login/begin", tags=["Authentication"])
def login_begin(payload: LoginBeginRequest | None = None) -> dict[str, object]:
    """Issue WebAuthn PublicKeyCredentialRequestOptions for passwordless login."""
    username = payload.username if payload is not None else None
    return svc.create_authentication_challenge(username=username)


@app.post(
    "/api/v1/auth/login/finish",
    response_model=AuthenticationReceipt,
    tags=["Authentication"],
)
def login_finish(payload: LoginFinishRequest) -> AuthenticationReceipt:
    """Verify WebAuthn assertion signature and return authentication receipt."""
    return svc.verify_authentication(
        challenge=payload.challenge,
        credential_id_b64=payload.credential_id_b64,
        client_data_b64=payload.client_data_b64,
        authenticator_data_b64=payload.authenticator_data_b64,
        signature_b64=payload.signature_b64,
    )


@app.get(
    "/api/v1/credentials/{username}",
    response_model=list[CredentialSummary],
    tags=["Credentials"],
)
def get_user_credentials(username: str) -> list[CredentialSummary]:
    """List registered passkey credentials for a user."""
    return svc.list_credentials(username)


@app.delete("/api/v1/credentials/{credential_id}", tags=["Credentials"])
def revoke_credential(credential_id: str) -> dict[str, str]:
    """Revoke and delete a registered passkey credential."""
    svc.revoke_credential(credential_id)
    return {"status": "revoked", "credential_id": credential_id}
