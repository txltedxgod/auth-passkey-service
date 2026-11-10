import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.fido.attestation import is_attestation_supported
from passkey.api import app
from passkey.cbor import (
    COSE_ALG_EDDSA,
    COSE_ALG_ES256,
    COSE_CRV_ED25519,
    COSE_CRV_P256,
    COSE_KTY_EC2,
    COSE_KTY_OKP,
    b64url_encode,
    encode_cbor,
)
from passkey.service import (
    AssertionVerificationError,
    AttestationVerificationError,
    CloneDetectedError,
    CredentialNotFoundError,
    DuplicateCredentialError,
    InvalidChallengeError,
    PasskeyService,
)


class VirtualAuthenticator:
    """In-test software WebAuthn authenticator producing spec-compliant COSE/CBOR payloads."""

    def __init__(self, alg: int = COSE_ALG_ES256, rp_id: str = "localhost") -> None:
        self.alg = alg
        self.rp_id = rp_id
        self.credential_id = os.urandom(16)
        self.aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.sign_count = 0

        if alg == COSE_ALG_ES256:
            self.private_key: Any = ec.generate_private_key(ec.SECP256R1())
            numbers = self.private_key.public_key().public_numbers()
            self.cose_key = encode_cbor(
                {
                    1: COSE_KTY_EC2,
                    3: COSE_ALG_ES256,
                    -1: COSE_CRV_P256,
                    -2: numbers.x.to_bytes(32, "big"),
                    -3: numbers.y.to_bytes(32, "big"),
                }
            )
        else:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
            raw_pub = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            self.cose_key = encode_cbor(
                {
                    1: COSE_KTY_OKP,
                    3: COSE_ALG_EDDSA,
                    -1: COSE_CRV_ED25519,
                    -2: raw_pub,
                }
            )

    def _sign(self, payload: bytes) -> bytes:
        if self.alg == COSE_ALG_ES256:
            return self.private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        return self.private_key.sign(payload)

    def _sign_with_cert_key(self, payload: bytes) -> tuple[bytes, bytes]:
        cert_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Passkey Test Attestation")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(cert_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=30))
            .sign(cert_key, hashes.SHA256())
        )
        sig = cert_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        return sig, cert.public_bytes(serialization.Encoding.DER)

    def make_registration(
        self,
        challenge: str,
        origin: str = "http://localhost:8000",
        rp_id: str | None = None,
        fmt: str = "none",
        up: bool = True,
        uv: bool = True,
    ) -> tuple[str, str]:
        client_bytes = json.dumps(
            {"type": "webauthn.create", "challenge": challenge, "origin": origin}
        ).encode("utf-8")
        client_hash = hashlib.sha256(client_bytes).digest()

        flags = (0x01 if up else 0) | (0x04 if uv else 0) | 0x40
        rp_hash = hashlib.sha256((rp_id or self.rp_id).encode("utf-8")).digest()
        auth_data = (
            rp_hash
            + bytes([flags])
            + self.sign_count.to_bytes(4, "big")
            + self.aaguid
            + len(self.credential_id).to_bytes(2, "big")
            + self.credential_id
            + self.cose_key
        )

        if fmt == "none":
            att_stmt: dict[str, Any] = {}
        elif fmt == "packed":
            sig = self._sign(auth_data + client_hash)
            att_stmt = {"alg": self.alg, "sig": sig}
        elif fmt == "packed-x5c":
            sig, cert_der = self._sign_with_cert_key(auth_data + client_hash)
            fmt = "packed"
            att_stmt = {"alg": COSE_ALG_ES256, "sig": sig, "x5c": [cert_der]}
        else:
            raise ValueError(f"Unsupported test fmt: {fmt}")

        att_obj = encode_cbor({"fmt": fmt, "attStmt": att_stmt, "authData": auth_data})
        return b64url_encode(client_bytes), b64url_encode(att_obj)

    def make_assertion(
        self,
        challenge: str,
        origin: str = "http://localhost:8000",
        rp_id: str | None = None,
        sign_count: int | None = None,
        up: bool = True,
        uv: bool = True,
    ) -> tuple[str, str, str]:
        if sign_count is None:
            self.sign_count += 1
            counter = self.sign_count
        else:
            counter = sign_count

        client_bytes = json.dumps(
            {"type": "webauthn.get", "challenge": challenge, "origin": origin}
        ).encode("utf-8")
        client_hash = hashlib.sha256(client_bytes).digest()

        flags = (0x01 if up else 0) | (0x04 if uv else 0)
        rp_hash = hashlib.sha256((rp_id or self.rp_id).encode("utf-8")).digest()
        auth_data = rp_hash + bytes([flags]) + counter.to_bytes(4, "big")
        signature = self._sign(auth_data + client_hash)
        return b64url_encode(client_bytes), b64url_encode(auth_data), b64url_encode(signature)


def test_passkey() -> None:
    svc = PasskeyService()
    res = svc.create_registration_challenge("alex")
    assert "challenge" in res
    assert res["rp"]["id"] == "localhost"
    assert res["user"]["name"] == "alex"


@pytest.mark.parametrize(
    ("alg", "fmt"),
    [
        (COSE_ALG_ES256, "none"),
        (COSE_ALG_ES256, "packed"),
        (COSE_ALG_ES256, "packed-x5c"),
        (COSE_ALG_EDDSA, "packed"),
    ],
)
def test_es256_and_eddsa_registration_and_login_flow(alg: int, fmt: str) -> None:
    svc = PasskeyService()
    auth = VirtualAuthenticator(alg=alg)

    reg_opts = svc.create_registration_challenge("alice")
    c_data, att_obj = auth.make_registration(reg_opts["challenge"], fmt=fmt)
    receipt = svc.complete_registration("alice", reg_opts["challenge"], c_data, att_obj, device_name="YubiKey")

    assert receipt.status == "registered"
    assert receipt.credential.algorithm == alg
    assert receipt.credential.username == "alice"

    cred_id = b64url_encode(auth.credential_id)
    for expected_counter in (1, 2):
        login_opts = svc.create_authentication_challenge("alice")
        assert login_opts["allowCredentials"][0]["id"] == cred_id
        lc, la, ls = auth.make_assertion(login_opts["challenge"], sign_count=expected_counter)
        auth_receipt = svc.verify_authentication(login_opts["challenge"], cred_id, lc, la, ls)
        assert auth_receipt.status == "authenticated"
        assert auth_receipt.username == "alice"
        assert auth_receipt.sign_count == expected_counter


def test_challenge_replay_and_expiration_rejected() -> None:
    svc = PasskeyService(challenge_ttl_seconds=60)
    auth = VirtualAuthenticator()
    reg_opts = svc.create_registration_challenge("bob")
    c_data, att_obj = auth.make_registration(reg_opts["challenge"])
    svc.complete_registration("bob", reg_opts["challenge"], c_data, att_obj)

    # Replaying consumed registration challenge must fail
    with pytest.raises(InvalidChallengeError):
        svc.complete_registration("bob", reg_opts["challenge"], c_data, att_obj)

    # Expired challenge must fail
    login_opts = svc.create_authentication_challenge("bob")
    svc._challenges[login_opts["challenge"]] = type(svc._challenges[login_opts["challenge"]])(
        challenge=login_opts["challenge"],
        purpose="authenticate",
        username="bob",
        expires_at=-1.0,
    )
    lc, la, ls = auth.make_assertion(login_opts["challenge"])
    with pytest.raises(InvalidChallengeError):
        svc.verify_authentication(login_opts["challenge"], b64url_encode(auth.credential_id), lc, la, ls)


def test_security_validations_origin_rp_flags_signature_and_clone() -> None:
    svc = PasskeyService(rp_id="example.com", allowed_origins={"https://example.com"})
    auth = VirtualAuthenticator(rp_id="example.com")

    # Wrong origin rejected and challenge consumed immediately
    reg1 = svc.create_registration_challenge("carol")
    c_bad, att_bad = auth.make_registration(reg1["challenge"], origin="https://evil.attacker")
    with pytest.raises(AttestationVerificationError, match="Untrusted origin"):
        svc.complete_registration("carol", reg1["challenge"], c_bad, att_bad)
    with pytest.raises(InvalidChallengeError):
        svc.complete_registration("carol", reg1["challenge"], c_bad, att_bad)

    # Wrong RP ID hash rejected
    reg2 = svc.create_registration_challenge("carol")
    c_rp, att_rp = auth.make_registration(reg2["challenge"], origin="https://example.com", rp_id="evil.com")
    with pytest.raises(AttestationVerificationError, match="RP ID hash"):
        svc.complete_registration("carol", reg2["challenge"], c_rp, att_rp)

    # User verification enforced when requested
    reg_uv = svc.create_registration_challenge("carol", require_user_verification=True)
    c_nouv, att_nouv = auth.make_registration(reg_uv["challenge"], origin="https://example.com", uv=False)
    with pytest.raises(AttestationVerificationError, match="User Verification"):
        svc.complete_registration("carol", reg_uv["challenge"], c_nouv, att_nouv)

    # Valid registration
    reg_ok = svc.create_registration_challenge("carol")
    c_ok, att_ok = auth.make_registration(reg_ok["challenge"], origin="https://example.com", fmt="packed")
    svc.complete_registration("carol", reg_ok["challenge"], c_ok, att_ok)
    cred_id = b64url_encode(auth.credential_id)

    # Duplicate credential enrollment rejected
    reg_dup = svc.create_registration_challenge("carol")
    c_dup, att_dup = auth.make_registration(reg_dup["challenge"], origin="https://example.com")
    with pytest.raises(DuplicateCredentialError):
        svc.complete_registration("carol", reg_dup["challenge"], c_dup, att_dup)

    # First assertion at sign_count=10 succeeds
    login1 = svc.create_authentication_challenge("carol")
    lc1, la1, ls1 = auth.make_assertion(login1["challenge"], origin="https://example.com", sign_count=10)
    svc.verify_authentication(login1["challenge"], cred_id, lc1, la1, ls1)

    # Forged signature rejected
    login_bad_sig = svc.create_authentication_challenge("carol")
    lc_f, la_f, ls_f = auth.make_assertion(login_bad_sig["challenge"], origin="https://example.com", sign_count=11)
    tampered_sig = b64url_encode(b"\x00" * 64)
    with pytest.raises(AssertionVerificationError, match="signature"):
        svc.verify_authentication(login_bad_sig["challenge"], cred_id, lc_f, la_f, tampered_sig)

    # Cloned authenticator with regressed sign_count <= 10 raises CloneDetectedError
    login_clone = svc.create_authentication_challenge("carol")
    lc_c, la_c, ls_c = auth.make_assertion(login_clone["challenge"], origin="https://example.com", sign_count=10)
    with pytest.raises(CloneDetectedError):
        svc.verify_authentication(login_clone["challenge"], cred_id, lc_c, la_c, ls_c)


def test_attestation_format_helpers() -> None:
    assert is_attestation_supported("none")
    assert is_attestation_supported("APPLE")
    assert not is_attestation_supported("tpm-unknown")


def test_http_api_full_passkey_lifecycle() -> None:
    client = TestClient(app)
    auth = VirtualAuthenticator(alg=COSE_ALG_ES256, rp_id="localhost")
    cred_id = b64url_encode(auth.credential_id)

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "healthy"

    # Legacy query endpoint still functions
    legacy = client.post("/api/v1/auth/register-challenge", params={"username": "legacy_user"})
    assert legacy.status_code == 200
    assert "challenge" in legacy.json()

    begin_reg = client.post(
        "/api/v1/auth/register/begin",
        json={"username": "http_user", "display_name": "HTTP User"},
    )
    assert begin_reg.status_code == 200
    reg_challenge = begin_reg.json()["challenge"]

    c_data, att_obj = auth.make_registration(reg_challenge, fmt="packed")
    finish_reg = client.post(
        "/api/v1/auth/register/finish",
        json={
            "username": "http_user",
            "challenge": reg_challenge,
            "client_data_b64": c_data,
            "attestation_object_b64": att_obj,
            "device_name": "Touch ID",
        },
    )
    assert finish_reg.status_code == 201
    assert finish_reg.json()["credential"]["device_name"] == "Touch ID"

    listed = client.get("/api/v1/credentials/http_user")
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0]["credential_id"] == cred_id

    begin_login = client.post("/api/v1/auth/login/begin", json={"username": "http_user"})
    assert begin_login.status_code == 200
    login_challenge = begin_login.json()["challenge"]

    lc, la, ls = auth.make_assertion(login_challenge, sign_count=1)
    finish_login = client.post(
        "/api/v1/auth/login/finish",
        json={
            "challenge": login_challenge,
            "credential_id_b64": cred_id,
            "client_data_b64": lc,
            "authenticator_data_b64": la,
            "signature_b64": ls,
        },
    )
    assert finish_login.status_code == 200
    assert finish_login.json()["status"] == "authenticated"
    assert finish_login.json()["sign_count"] == 1

    # Revoke credential and confirm subsequent deletion/login return 404
    revoked = client.delete(f"/api/v1/credentials/{cred_id}")
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    not_found = client.delete(f"/api/v1/credentials/{cred_id}")
    assert not_found.status_code == 404
    assert not_found.json()["error"] == CredentialNotFoundError.__name__
