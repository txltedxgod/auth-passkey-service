"""Pydantic v2 request and response schemas for WebAuthn passkey flows."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class RegisterBeginRequest(BaseModel):
    """Payload to initiate WebAuthn credential registration."""

    username: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    require_user_verification: bool = Field(default=False)


class RegisterFinishRequest(BaseModel):
    """Client attestation response submitted to complete passkey registration."""

    username: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    challenge: str = Field(..., min_length=16, max_length=256)
    client_data_b64: str = Field(..., min_length=8)
    attestation_object_b64: str = Field(..., min_length=8)
    device_name: str | None = Field(default=None, max_length=100)


class LoginBeginRequest(BaseModel):
    """Payload to start passwordless WebAuthn authentication."""

    username: str | None = Field(default=None, min_length=2, max_length=64)


class LoginFinishRequest(BaseModel):
    """Client assertion response verified during WebAuthn login."""

    challenge: str = Field(..., min_length=16, max_length=256)
    credential_id_b64: str = Field(..., min_length=8)
    client_data_b64: str = Field(..., min_length=8)
    authenticator_data_b64: str = Field(..., min_length=8)
    signature_b64: str = Field(..., min_length=8)


class CredentialSummary(BaseModel):
    """Public metadata for a registered passkey credential."""

    credential_id: str
    username: str
    algorithm: int
    sign_count: int
    aaguid: str
    attestation_format: str
    device_name: str | None = None
    created_at: datetime
    last_used_at: datetime | None = None


class RegistrationReceipt(BaseModel):
    """Response returned after successful WebAuthn attestation verification."""

    status: str = "registered"
    credential: CredentialSummary


class AuthenticationReceipt(BaseModel):
    """Response returned after successful WebAuthn assertion verification."""

    status: str = "authenticated"
    username: str
    credential_id: str
    sign_count: int
    user_verified: bool
    authenticated_at: datetime
    details: dict[str, Any] = Field(default_factory=dict)
