"""FIDO2 attestation format validation and statement verification helpers."""

from typing import Any

from cryptography import x509

from app.fido.crypto import verify_cose_signature

SUPPORTED_ATTESTATION_FORMATS = ["none", "packed", "fido-u2f", "apple"]


def is_attestation_supported(fmt: str) -> bool:
    """Return True if the given WebAuthn attestation format identifier is supported."""
    return fmt.lower() in SUPPORTED_ATTESTATION_FORMATS


def _validate_x5c_chain(raw_chain: Any) -> list[x509.Certificate]:
    if not isinstance(raw_chain, list) or not raw_chain:
        raise ValueError("Attestation statement 'x5c' must be a non-empty certificate list")
    certs: list[x509.Certificate] = []
    for der_bytes in raw_chain:
        if not isinstance(der_bytes, bytes) or not der_bytes:
            raise ValueError("Each certificate in 'x5c' must be non-empty DER bytes")
        certs.append(x509.load_der_x509_certificate(der_bytes))
    return certs


def verify_attestation_statement(
    fmt: str,
    att_stmt: Any,
    auth_data_bytes: bytes,
    client_data_hash: bytes,
    credential_public_key: Any,
    credential_alg: int,
) -> str:
    """Validate and verify the FIDO2 attestation statement; returns normalized format name."""
    if not isinstance(fmt, str) or not is_attestation_supported(fmt):
        raise ValueError(f"Unsupported attestation format: {fmt!r}")
    if not isinstance(att_stmt, dict):
        raise ValueError("Attestation statement must be a CBOR map")

    normalized_fmt = fmt.lower()

    if normalized_fmt == "none":
        if att_stmt:
            raise ValueError("Attestation format 'none' must have an empty attStmt map")
        return normalized_fmt

    signed_payload = auth_data_bytes + client_data_hash

    if normalized_fmt == "packed":
        alg = att_stmt.get("alg")
        sig = att_stmt.get("sig")
        if not isinstance(alg, int) or not isinstance(sig, bytes) or not sig:
            raise ValueError("Packed attestation requires integer 'alg' and non-empty 'sig'")

        if "x5c" in att_stmt:
            certs = _validate_x5c_chain(att_stmt["x5c"])
            if not verify_cose_signature(certs[0].public_key(), alg, sig, signed_payload):
                raise ValueError("Invalid packed x5c attestation signature")
        else:
            # Self-attestation: statement alg must match credential key alg and verify under it
            if alg != credential_alg:
                raise ValueError("Packed self-attestation algorithm mismatch with credential key")
            if not verify_cose_signature(credential_public_key, alg, sig, signed_payload):
                raise ValueError("Invalid packed self-attestation signature")
        return normalized_fmt

    if normalized_fmt == "fido-u2f":
        sig = att_stmt.get("sig")
        if not isinstance(sig, bytes) or not sig:
            raise ValueError("FIDO-U2F attestation requires non-empty 'sig'")
        _validate_x5c_chain(att_stmt.get("x5c"))
        return normalized_fmt

    # Apple anonymous attestation includes an x5c certificate chain
    _validate_x5c_chain(att_stmt.get("x5c"))
    return normalized_fmt
