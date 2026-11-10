"""FIDO2 / WebAuthn cryptographic verification helpers."""

from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

COSE_ALG_ES256 = -7
COSE_ALG_EDDSA = -8


def verify_cose_signature(
    public_key: Any,
    alg: int,
    signature: bytes,
    signed_data: bytes,
) -> bool:
    """Verify a WebAuthn signature against signed_data using the stored COSE key."""
    try:
        if alg == COSE_ALG_ES256 and isinstance(public_key, ec.EllipticCurvePublicKey):
            # Support both ASN.1 DER signatures (WebAuthn) and raw 64-byte IEEE P1363
            der_sig = signature
            if len(signature) == 64 and signature[0] != 0x30:
                r = int.from_bytes(signature[:32], "big")
                s = int.from_bytes(signature[32:], "big")
                der_sig = encode_dss_signature(r, s)
            public_key.verify(der_sig, signed_data, ec.ECDSA(hashes.SHA256()))
            return True

        if alg == COSE_ALG_EDDSA and isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, signed_data)
            return True
    except (InvalidSignature, ValueError):
        return False
    return False
