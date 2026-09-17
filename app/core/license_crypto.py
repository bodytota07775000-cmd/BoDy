"""License key generation and validation.

Uses HMAC-SHA256 with a secret key to create license keys that are
tied to a specific hardware fingerprint and expiry date.

Key format: base64(fingerprint_hash + expiry_timestamp + hmac_signature)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
from datetime import datetime


# Secret key for HMAC signing — change this for each build!
LICENSE_SECRET = b"erp-license-secret-key-2024-change-me"


def generate_license_key(
    fingerprint: str,
    expires_at: datetime | None = None,
    max_users: int = 1,
    features: list[str] | None = None,
    secret: bytes = LICENSE_SECRET,
) -> str:
    """Generate a license key for a specific machine fingerprint.

    Args:
        fingerprint: Hardware fingerprint hash
        expires_at: Expiry date (None = lifetime)
        max_users: Maximum concurrent users
        features: List of allowed features
        secret: HMAC secret key

    Returns:
        License key string
    """
    payload = {
        "fp": fingerprint[:16],  # First 16 chars of fingerprint
        "exp": expires_at.isoformat() if expires_at else None,
        "max": max_users,
        "feat": features or ["all"],
    }

    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    signature = hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()

    key_data = {
        "p": base64.b64encode(payload_bytes).decode("utf-8"),
        "s": signature,
    }

    key_bytes = json.dumps(key_data, sort_keys=True).encode("utf-8")
    return base64.b64encode(key_bytes).decode("utf-8")


def validate_license_key(
    key: str,
    fingerprint: str,
    secret: bytes = LICENSE_SECRET,
) -> dict | None:
    """Validate a license key against the current machine fingerprint.

    Args:
        key: License key to validate
        fingerprint: Current machine's hardware fingerprint
        secret: HMAC secret key

    Returns:
        Decoded payload dict if valid, None if invalid
    """
    try:
        key_bytes = base64.b64decode(key.encode("utf-8"))
        key_data = json.loads(key_bytes)

        payload_b64 = key_data["p"]
        signature = key_data["s"]

        payload_bytes = base64.b64decode(payload_b64.encode("utf-8"))

        expected_sig = hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            return None

        payload = json.loads(payload_bytes)

        # Verify fingerprint matches (first 16 chars)
        if payload["fp"] != fingerprint[:16]:
            return None

        # Check expiry
        if payload.get("exp"):
            expires_at = datetime.fromisoformat(payload["exp"])
            if datetime.now() > expires_at:
                return None

        return payload

    except Exception:
        return None


def get_license_info(key: str, secret: bytes = LICENSE_SECRET) -> dict | None:
    """Decode license info without validation (for display purposes)."""
    try:
        key_bytes = base64.b64decode(key.encode("utf-8"))
        key_data = json.loads(key_bytes)
        payload_bytes = base64.b64decode(key_data["p"].encode("utf-8"))
        return json.loads(payload_bytes)
    except Exception:
        return None
