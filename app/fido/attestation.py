"""
FIDO2 Attestation Formats Verification Helper
"""

SUPPORTED_ATTESTATION_FORMATS = ["none", "packed", "fido-u2f", "apple"]

def is_attestation_supported(fmt: str) -> bool:
    return fmt.lower() in SUPPORTED_ATTESTATION_FORMATS
