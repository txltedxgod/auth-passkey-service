"""WebAuthn / FIDO2 passkey authentication service with real cryptographic verification."""

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.fido.attestation import verify_attestation_statement
from app.fido.crypto import COSE_ALG_EDDSA, COSE_ALG_ES256, verify_cose_signature
from passkey.cbor import (
    AuthenticatorData,
    b64url_decode,
    b64url_encode,
    decode_cbor,
    parse_authenticator_data,
)
from passkey.schemas import (
    AuthenticationReceipt,
    CredentialSummary,
    RegistrationReceipt,
)

DEFAULT_ALLOWED_ORIGINS = frozenset({"http://localhost:8000", "https://localhost"})


class PasskeyError(Exception):
    """Base domain error mapped cleanly to HTTP error responses."""

    def __init__(self, detail: str, status_code: int = 400) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


class InvalidChallengeError(PasskeyError):
    """Raised when a WebAuthn challenge is missing, expired, replayed, or mismatched."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail, status_code=401)


class AttestationVerificationError(PasskeyError):
    """Raised when FIDO2 registration attestation verification fails."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail, status_code=400)


class AssertionVerificationError(PasskeyError):
    """Raised when WebAuthn login assertion signature or RP/flag validation fails."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail, status_code=401)


class CloneDetectedError(PasskeyError):
    """Raised when incoming signCount indicates a cloned or replayed authenticator."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail, status_code=403)


class CredentialNotFoundError(PasskeyError):
    """Raised when requested passkey credential or user passkeys do not exist."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail, status_code=404)


class DuplicateCredentialError(PasskeyError):
    """Raised when attempting to register an already enrolled credential ID."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail, status_code=409)


@dataclass(frozen=True)
class PendingChallenge:
    """Single-use issued WebAuthn challenge entry."""

    challenge: str
    purpose: str
    username: str | None
    expires_at: float
    require_uv: bool = False


@dataclass
class StoredCredential:
    """Registered WebAuthn passkey record."""

    credential_id: str
    username: str
    public_key: Any
    algorithm: int
    sign_count: int
    aaguid: str
    attestation_format: str
    device_name: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_used_at: datetime | None = None

    def to_summary(self) -> CredentialSummary:
        return CredentialSummary(
            credential_id=self.credential_id,
            username=self.username,
            algorithm=self.algorithm,
            sign_count=self.sign_count,
            aaguid=self.aaguid,
            attestation_format=self.attestation_format,
            device_name=self.device_name,
            created_at=self.created_at,
            last_used_at=self.last_used_at,
        )


def _validate_client_data(
    client_data_b64: str,
    expected_type: str,
    expected_challenge: str,
    allowed_origins: frozenset[str],
    error_cls: type[PasskeyError],
) -> tuple[dict[str, Any], bytes]:
    try:
        raw_bytes = b64url_decode(client_data_b64)
        client_data = json.loads(raw_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise error_cls(f"Malformed clientDataJSON: {exc}") from exc

    if not isinstance(client_data, dict):
        raise error_cls("clientDataJSON must decode to a JSON object")

    if client_data.get("type") != expected_type:
        raise error_cls(f"Unexpected clientDataJSON type: {client_data.get('type')!r}")

    incoming_challenge = client_data.get("challenge")
    if not isinstance(incoming_challenge, str) or not hmac.compare_digest(
        incoming_challenge, expected_challenge
    ):
        raise error_cls("clientDataJSON challenge mismatch")

    origin = client_data.get("origin")
    if not isinstance(origin, str) or origin not in allowed_origins:
        raise error_cls(f"Untrusted origin in clientDataJSON: {origin!r}")

    return client_data, hashlib.sha256(raw_bytes).digest()


def _validate_rp_and_flags(
    auth_data: AuthenticatorData,
    expected_rp_hash: bytes,
    require_uv: bool,
    error_cls: type[PasskeyError],
) -> None:
    if not hmac.compare_digest(auth_data.rp_id_hash, expected_rp_hash):
        raise error_cls("RP ID hash verification failed")
    if not auth_data.user_present:
        raise error_cls("User Present (UP) flag is not set")
    if require_uv and not auth_data.user_verified:
        raise error_cls("User Verification (UV) flag is required")


class PasskeyService:
    """In-memory WebAuthn/FIDO2 relying-party engine."""

    def __init__(
        self,
        rp_id: str = "localhost",
        rp_name: str = "Passkey Security Portal",
        allowed_origins: set[str] | frozenset[str] | None = None,
        challenge_ttl_seconds: int = 300,
        require_uv: bool = False,
    ) -> None:
        if challenge_ttl_seconds <= 0:
            raise ValueError("challenge_ttl_seconds must be positive")
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.allowed_origins = (
            frozenset(allowed_origins) if allowed_origins is not None else DEFAULT_ALLOWED_ORIGINS
        )
        self.challenge_ttl_seconds = challenge_ttl_seconds
        self.require_uv = require_uv
        self._rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        self._challenges: dict[str, PendingChallenge] = {}
        self._credentials: dict[str, StoredCredential] = {}
        self._user_credentials: dict[str, list[str]] = {}
        self._user_handles: dict[str, str] = {}

    def _evict_expired_challenges(self) -> None:
        now = time.monotonic()
        expired = [key for key, item in self._challenges.items() if item.expires_at <= now]
        for key in expired:
            del self._challenges[key]

    def _issue_challenge(
        self,
        purpose: str,
        username: str | None,
        require_uv: bool = False,
    ) -> PendingChallenge:
        self._evict_expired_challenges()
        challenge = b64url_encode(secrets.token_bytes(32))
        entry = PendingChallenge(
            challenge=challenge,
            purpose=purpose,
            username=username,
            expires_at=time.monotonic() + self.challenge_ttl_seconds,
            require_uv=require_uv,
        )
        self._challenges[challenge] = entry
        return entry

    def _consume_challenge(self, challenge: str, expected_purpose: str) -> PendingChallenge:
        # Always consume immediately (pop) to prevent replay or validation-oracle probing
        pending = self._challenges.pop(challenge, None)
        if pending is None:
            raise InvalidChallengeError("Unknown, expired, or already used challenge")
        if time.monotonic() > pending.expires_at:
            raise InvalidChallengeError("Challenge has expired")
        if pending.purpose != expected_purpose:
            raise InvalidChallengeError(
                f"Challenge was issued for '{pending.purpose}', not '{expected_purpose}'"
            )
        return pending

    def create_registration_challenge(
        self,
        username: str,
        display_name: str | None = None,
        require_user_verification: bool = False,
    ) -> dict[str, Any]:
        """Generate PublicKeyCredentialCreationOptions and track a single-use challenge."""
        pending = self._issue_challenge(
            purpose="register",
            username=username,
            require_uv=require_user_verification,
        )
        user_handle = self._user_handles.setdefault(username, secrets.token_hex(8))
        existing_ids = self._user_credentials.get(username, [])
        return {
            "challenge": pending.challenge,
            "rp": {"name": self.rp_name, "id": self.rp_id},
            "user": {
                "id": user_handle,
                "name": username,
                "displayName": display_name or username,
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": COSE_ALG_ES256},
                {"type": "public-key", "alg": COSE_ALG_EDDSA},
            ],
            "timeout": self.challenge_ttl_seconds * 1000,
            "attestation": "direct",
            "authenticatorSelection": {
                "residentKey": "preferred",
                "userVerification": (
                    "required" if (require_user_verification or self.require_uv) else "preferred"
                ),
            },
            "excludeCredentials": [
                {"type": "public-key", "id": cred_id} for cred_id in existing_ids
            ],
        }

    def complete_registration(
        self,
        username: str,
        challenge: str,
        client_data_b64: str,
        attestation_object_b64: str,
        device_name: str | None = None,
    ) -> RegistrationReceipt:
        """Verify clientDataJSON + FIDO2 attestationObject and store credential public key."""
        pending = self._consume_challenge(challenge, expected_purpose="register")
        if pending.username != username:
            raise InvalidChallengeError("Challenge does not match the specified username")

        _, client_data_hash = _validate_client_data(
            client_data_b64=client_data_b64,
            expected_type="webauthn.create",
            expected_challenge=challenge,
            allowed_origins=self.allowed_origins,
            error_cls=AttestationVerificationError,
        )

        try:
            att_obj = decode_cbor(b64url_decode(attestation_object_b64))
        except ValueError as exc:
            raise AttestationVerificationError(f"Malformed CBOR attestationObject: {exc}") from exc

        if not isinstance(att_obj, dict):
            raise AttestationVerificationError("attestationObject must decode to a CBOR map")

        auth_data_bytes = att_obj.get("authData")
        if not isinstance(auth_data_bytes, bytes):
            raise AttestationVerificationError("attestationObject missing 'authData' bytes")

        try:
            parsed = parse_authenticator_data(auth_data_bytes, expect_attested_data=True)
        except ValueError as exc:
            raise AttestationVerificationError(f"Invalid authenticatorData: {exc}") from exc

        _validate_rp_and_flags(
            parsed,
            expected_rp_hash=self._rp_id_hash,
            require_uv=pending.require_uv or self.require_uv,
            error_cls=AttestationVerificationError,
        )

        assert parsed.credential_id is not None and parsed.algorithm is not None

        try:
            normalized_fmt = verify_attestation_statement(
                fmt=att_obj.get("fmt", ""),
                att_stmt=att_obj.get("attStmt"),
                auth_data_bytes=auth_data_bytes,
                client_data_hash=client_data_hash,
                credential_public_key=parsed.public_key,
                credential_alg=parsed.algorithm,
            )
        except ValueError as exc:
            raise AttestationVerificationError(str(exc)) from exc

        cred_id_b64 = b64url_encode(parsed.credential_id)
        if cred_id_b64 in self._credentials:
            raise DuplicateCredentialError(f"Credential '{cred_id_b64}' is already registered")

        stored = StoredCredential(
            credential_id=cred_id_b64,
            username=username,
            public_key=parsed.public_key,
            algorithm=parsed.algorithm,
            sign_count=parsed.sign_count,
            aaguid=parsed.aaguid or "00000000-0000-0000-0000-000000000000",
            attestation_format=normalized_fmt,
            device_name=device_name,
        )
        self._credentials[cred_id_b64] = stored
        self._user_credentials.setdefault(username, []).append(cred_id_b64)
        return RegistrationReceipt(credential=stored.to_summary())

    def create_authentication_challenge(self, username: str | None = None) -> dict[str, Any]:
        """Issue WebAuthn PublicKeyCredentialRequestOptions for login assertion."""
        allow_ids: list[str] = []
        if username is not None:
            allow_ids = self._user_credentials.get(username, [])
            if not allow_ids:
                raise CredentialNotFoundError(f"No passkeys registered for '{username}'")

        pending = self._issue_challenge(
            purpose="authenticate",
            username=username,
            require_uv=self.require_uv,
        )
        return {
            "challenge": pending.challenge,
            "timeout": self.challenge_ttl_seconds * 1000,
            "rpId": self.rp_id,
            "userVerification": "required" if self.require_uv else "preferred",
            "allowCredentials": [
                {"type": "public-key", "id": cred_id} for cred_id in allow_ids
            ],
        }

    def verify_authentication(
        self,
        challenge: str,
        credential_id_b64: str,
        client_data_b64: str,
        authenticator_data_b64: str,
        signature_b64: str,
    ) -> AuthenticationReceipt:
        """Verify WebAuthn login assertion signature, RP ID hash, flags, and anti-clone counter."""
        pending = self._consume_challenge(challenge, expected_purpose="authenticate")

        _, client_data_hash = _validate_client_data(
            client_data_b64=client_data_b64,
            expected_type="webauthn.get",
            expected_challenge=challenge,
            allowed_origins=self.allowed_origins,
            error_cls=AssertionVerificationError,
        )

        stored = self._credentials.get(credential_id_b64)
        if stored is None:
            raise CredentialNotFoundError(f"Unknown credential '{credential_id_b64}'")

        if pending.username is not None and stored.username != pending.username:
            raise AssertionVerificationError("Credential does not belong to requested user")

        try:
            raw_auth_data = b64url_decode(authenticator_data_b64)
            parsed = parse_authenticator_data(raw_auth_data, expect_attested_data=False)
            sig_bytes = b64url_decode(signature_b64)
        except ValueError as exc:
            raise AssertionVerificationError(f"Malformed assertion payload: {exc}") from exc

        _validate_rp_and_flags(
            parsed,
            expected_rp_hash=self._rp_id_hash,
            require_uv=pending.require_uv or self.require_uv,
            error_cls=AssertionVerificationError,
        )

        signed_payload = raw_auth_data + client_data_hash
        if not verify_cose_signature(
            stored.public_key, stored.algorithm, sig_bytes, signed_payload
        ):
            raise AssertionVerificationError("Cryptographic assertion signature verification failed")

        # WebAuthn §7.2 step 21: counter regression when non-zero indicates credential cloning
        if (stored.sign_count > 0 or parsed.sign_count > 0) and parsed.sign_count <= stored.sign_count:
            raise CloneDetectedError(
                f"Authenticator counter regression detected "
                f"(stored={stored.sign_count}, incoming={parsed.sign_count})"
            )

        now = datetime.now(UTC)
        stored.sign_count = parsed.sign_count
        stored.last_used_at = now
        return AuthenticationReceipt(
            username=stored.username,
            credential_id=stored.credential_id,
            sign_count=stored.sign_count,
            user_verified=parsed.user_verified,
            authenticated_at=now,
            details={"aaguid": stored.aaguid, "algorithm": stored.algorithm},
        )

    def list_credentials(self, username: str) -> list[CredentialSummary]:
        """List registered passkey summaries for a user."""
        cred_ids = self._user_credentials.get(username, [])
        return [
            self._credentials[cid].to_summary()
            for cid in cred_ids
            if cid in self._credentials
        ]

    def revoke_credential(self, credential_id: str) -> None:
        """Delete a registered passkey credential."""
        stored = self._credentials.pop(credential_id, None)
        if stored is None:
            raise CredentialNotFoundError(f"Credential '{credential_id}' not found")
        user_list = self._user_credentials.get(stored.username)
        if user_list and credential_id in user_list:
            user_list.remove(credential_id)
