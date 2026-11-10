"""Minimal RFC 8949 CBOR codec, COSE key decoder, and WebAuthn authenticatorData parser."""

import base64
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from app.fido.crypto import COSE_ALG_EDDSA, COSE_ALG_ES256

COSE_KTY_OKP = 1
COSE_KTY_EC2 = 2

COSE_CRV_P256 = 1
COSE_CRV_ED25519 = 6

_MAX_CBOR_DEPTH = 16


def b64url_encode(data: bytes) -> str:
    """Encode raw bytes into unpadded base64url text."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    """Decode padded or unpadded base64url string into raw bytes."""
    if not value:
        raise ValueError("Empty base64url payload")
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _read_uint(buf: bytes, offset: int, addl: int) -> tuple[int, int]:
    if addl < 24:
        return addl, offset
    width_map = {24: 1, 25: 2, 26: 4, 27: 8}
    width = width_map.get(addl)
    if width is None:
        raise ValueError(f"Unsupported CBOR additional info: {addl}")
    end = offset + width
    if end > len(buf):
        raise ValueError("Truncated CBOR integer")
    return int.from_bytes(buf[offset:end], "big"), end


def decode_cbor_prefix(buf: bytes, offset: int = 0, depth: int = 0) -> tuple[Any, int]:
    """Decode one CBOR item starting at offset and return (value, next_offset)."""
    if depth > _MAX_CBOR_DEPTH:
        raise ValueError("CBOR nesting depth exceeded")
    if offset >= len(buf):
        raise ValueError("Unexpected end of CBOR input")

    initial = buf[offset]
    major = initial >> 5
    addl = initial & 0x1F
    offset += 1

    if major == 0:
        val, next_off = _read_uint(buf, offset, addl)
        return val, next_off

    if major == 1:
        val, next_off = _read_uint(buf, offset, addl)
        return -1 - val, next_off

    if major in (2, 3):
        length, next_off = _read_uint(buf, offset, addl)
        end = next_off + length
        if end > len(buf):
            raise ValueError("Truncated CBOR byte/text string")
        raw = buf[next_off:end]
        return (bytes(raw) if major == 2 else raw.decode("utf-8")), end

    if major == 4:
        count, next_off = _read_uint(buf, offset, addl)
        items = []
        for _ in range(count):
            item, next_off = decode_cbor_prefix(buf, next_off, depth + 1)
            items.append(item)
        return items, next_off

    if major == 5:
        count, next_off = _read_uint(buf, offset, addl)
        mapping: dict[Any, Any] = {}
        for _ in range(count):
            key, next_off = decode_cbor_prefix(buf, next_off, depth + 1)
            if isinstance(key, (dict, list)):
                raise ValueError("Unhashable CBOR map key")
            value, next_off = decode_cbor_prefix(buf, next_off, depth + 1)
            mapping[key] = value
        return mapping, next_off

    if major == 7:
        if addl == 20:
            return False, offset
        if addl == 21:
            return True, offset
        if addl in (22, 23):
            return None, offset
        raise ValueError(f"Unsupported CBOR simple value: {addl}")

    raise ValueError(f"Unsupported CBOR major type: {major}")


def decode_cbor(buf: bytes) -> Any:
    """Decode a full CBOR buffer, rejecting trailing unconsumed bytes."""
    value, next_off = decode_cbor_prefix(buf, 0)
    if next_off != len(buf):
        raise ValueError("Trailing bytes after CBOR payload")
    return value


def _encode_uint_header(major: int, value: int) -> bytes:
    prefix = major << 5
    if value < 24:
        return bytes([prefix | value])
    if value < 256:
        return bytes([prefix | 24, value])
    if value < 65536:
        return bytes([prefix | 25]) + value.to_bytes(2, "big")
    if value < 2**32:
        return bytes([prefix | 26]) + value.to_bytes(4, "big")
    return bytes([prefix | 27]) + value.to_bytes(8, "big")


def encode_cbor(value: Any) -> bytes:
    """Encode Python primitives (int, bytes, str, bool, None, list, dict) into CBOR."""
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        if value >= 0:
            return _encode_uint_header(0, value)
        return _encode_uint_header(1, -1 - value)
    if isinstance(value, bytes):
        return _encode_uint_header(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _encode_uint_header(3, len(encoded)) + encoded
    if isinstance(value, list):
        return _encode_uint_header(4, len(value)) + b"".join(encode_cbor(item) for item in value)
    if isinstance(value, dict):
        chunks = [_encode_uint_header(5, len(value))]
        for k, v in value.items():
            chunks.append(encode_cbor(k))
            chunks.append(encode_cbor(v))
        return b"".join(chunks)
    raise TypeError(f"Unsupported type for CBOR encoding: {type(value).__name__}")


def parse_cose_public_key_prefix(buf: bytes, offset: int = 0) -> tuple[Any, int, int]:
    """Decode a COSE public key map starting at offset -> (public_key, alg, next_offset)."""
    cose_map, next_off = decode_cbor_prefix(buf, offset)
    if not isinstance(cose_map, dict):
        raise ValueError("COSE public key must be a CBOR map")

    kty = cose_map.get(1)
    alg = cose_map.get(3)
    crv = cose_map.get(-1)

    if kty == COSE_KTY_EC2 and alg == COSE_ALG_ES256 and crv == COSE_CRV_P256:
        x = cose_map.get(-2)
        y = cose_map.get(-3)
        if not isinstance(x, bytes) or not isinstance(y, bytes) or len(x) != 32 or len(y) != 32:
            raise ValueError("Invalid P-256 EC2 coordinates in COSE key")
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"),
            int.from_bytes(y, "big"),
            ec.SECP256R1(),
        )
        return numbers.public_key(), COSE_ALG_ES256, next_off

    if kty == COSE_KTY_OKP and alg == COSE_ALG_EDDSA and crv == COSE_CRV_ED25519:
        x = cose_map.get(-2)
        if not isinstance(x, bytes) or len(x) != 32:
            raise ValueError("Invalid Ed25519 public key bytes in COSE key")
        return ed25519.Ed25519PublicKey.from_public_bytes(x), COSE_ALG_EDDSA, next_off

    raise ValueError(f"Unsupported COSE key parameters: kty={kty}, alg={alg}, crv={crv}")


@dataclass(frozen=True)
class AuthenticatorData:
    """Parsed W3C WebAuthn authenticatorData structure."""

    rp_id_hash: bytes
    flags: int
    sign_count: int
    user_present: bool
    user_verified: bool
    attested_data_included: bool
    extension_data_included: bool
    aaguid: str | None = None
    credential_id: bytes | None = None
    public_key: Any | None = None
    algorithm: int | None = None


def parse_authenticator_data(
    raw: bytes,
    expect_attested_data: bool = False,
) -> AuthenticatorData:
    """Parse binary authenticatorData and optional attestedCredentialData."""
    if len(raw) < 37:
        raise ValueError("authenticatorData must be at least 37 bytes")

    rp_id_hash = raw[:32]
    flags = raw[32]
    sign_count = int.from_bytes(raw[33:37], "big")

    user_present = bool(flags & 0x01)
    user_verified = bool(flags & 0x04)
    attested_data_included = bool(flags & 0x40)
    extension_data_included = bool(flags & 0x80)

    aaguid_hex: str | None = None
    credential_id: bytes | None = None
    public_key: Any | None = None
    algorithm: int | None = None

    if expect_attested_data:
        if not attested_data_included:
            raise ValueError("AT flag must be set during credential registration")
        if len(raw) < 55:
            raise ValueError("Truncated attestedCredentialData header")

        aaguid_bytes = raw[37:53]
        aaguid_hex = (
            f"{aaguid_bytes[0:4].hex()}-{aaguid_bytes[4:6].hex()}-"
            f"{aaguid_bytes[6:8].hex()}-{aaguid_bytes[8:10].hex()}-{aaguid_bytes[10:16].hex()}"
        )
        cred_id_len = int.from_bytes(raw[53:55], "big")
        if cred_id_len == 0 or cred_id_len > 1023:
            raise ValueError(f"Invalid credentialIdLength: {cred_id_len}")

        cred_end = 55 + cred_id_len
        if len(raw) <= cred_end:
            raise ValueError("Truncated credentialId or missing COSE public key")

        credential_id = raw[55:cred_end]
        public_key, algorithm, next_off = parse_cose_public_key_prefix(raw, cred_end)

        if not extension_data_included and next_off != len(raw):
            raise ValueError("Unexpected trailing bytes in authenticatorData")
    elif not extension_data_included and len(raw) != 37:
        raise ValueError("Unexpected trailing bytes in assertion authenticatorData")

    return AuthenticatorData(
        rp_id_hash=rp_id_hash,
        flags=flags,
        sign_count=sign_count,
        user_present=user_present,
        user_verified=user_verified,
        attested_data_included=attested_data_included,
        extension_data_included=extension_data_included,
        aaguid=aaguid_hex,
        credential_id=credential_id,
        public_key=public_key,
        algorithm=algorithm,
    )
