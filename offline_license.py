"""
Offline License Generator
Creates encrypted .lic files that work without server connection.

Usage:
    python generate_license.py --hwid <HWID> --name "Client Name" --days 365
    python generate_license.py --hwid <HWID> --name "Client Name" --permanent
"""
import argparse
import hashlib
import json
import os
import secrets
import struct
import time
from datetime import datetime, timedelta
from pathlib import Path

# Secret key - CHANGE THIS for each deployment!
SECRET_KEY = b"erp-offline-license-secret-2024"


def derive_key(hwid: str) -> bytes:
    """Derive an encryption key from the hardware ID."""
    return hashlib.pbkdf2_hmac("sha256", SECRET_KEY, hwid.encode(), 100000)


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """Simple XOR encryption with key cycling."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def generate_license_file(
    hwid: str,
    customer_name: str,
    customer_phone: str = "",
    days: int | None = None,
    max_users: int = 1,
    features: list[str] | None = None,
    output_dir: str = ".",
) -> str:
    """Generate an encrypted .lic file."""
    
    # Calculate expiry
    if days is not None:
        expiry = datetime.now() + timedelta(days=days)
        expiry_str = expiry.strftime("%Y-%m-%d")
    else:
        expiry_str = "permanent"
    
    # License data
    license_data = {
        "v": 1,  # version
        "hwid": hwid.upper(),
        "name": customer_name,
        "phone": customer_phone,
        "exp": expiry_str,
        "max": max_users,
        "feat": features or ["all"],
        "created": datetime.now().isoformat(),
        "id": secrets.token_hex(8),
    }
    
    # Serialize to JSON
    data_str = json.dumps(license_data, separators=(",", ":"))
    data_bytes = data_str.encode("utf-8")
    
    # Generate signature
    key = derive_key(hwid)
    signature = hashlib.sha256(key + data_bytes + SECRET_KEY).hexdigest()[:32]
    
    # Build license content: signature + encrypted data
    encrypted = xor_encrypt(data_bytes, key)
    
    # Encode as base64-like (URL safe)
    import base64
    encoded = base64.urlsafe_b64encode(encrypted).decode()
    
    # Final license file content
    lic_content = f"ERPOFFLINE-1\n{hwid.upper()[:16]}\n{signature}\n{encoded}\n"
    
    # Write file
    output_path = Path(output_dir) / f"license_{customer_name.replace(' ', '_')}.lic"
    output_path.write_text(lic_content, encoding="utf-8")
    
    print(f"License file created: {output_path}")
    print(f"  Customer: {customer_name}")
    print(f"  HWID: {hwid[:32]}...")
    print(f"  Expiry: {expiry_str}")
    print(f"  Max Users: {max_users}")
    print(f"  Signature: {signature}")
    
    return str(output_path)


def verify_license_file(lic_path: str, current_hwid: str) -> dict | None:
    """Verify a .lic file against current hardware ID. Returns license data if valid."""
    try:
        content = Path(lic_path).read_text(encoding="utf-8")
        lines = content.strip().split("\n")
        
        if len(lines) != 5 or lines[0] != "ERPOFFLINE-1":
            return None
        
        file_hwid = lines[1]
        file_signature = lines[2]
        encoded_data = lines[3]
        
        # Decrypt
        key = derive_key(current_hwid)
        import base64
        encrypted = base64.urlsafe_b64decode(encoded_data)
        data_bytes = xor_encrypt(encrypted, key)
        
        # Verify signature
        expected_sig = hashlib.sha256(key + data_bytes + SECRET_KEY).hexdigest()[:32]
        if file_signature != expected_sig:
            return None
        
        # Parse license data
        license_data = json.loads(data_bytes.decode("utf-8"))
        
        # Verify HWID matches
        if license_data["hwid"] != current_hwid.upper():
            return None
        
        # Check expiry
        if license_data["exp"] != "permanent":
            exp_date = datetime.strptime(license_data["exp"], "%Y-%m-%d")
            if datetime.now() > exp_date:
                return None  # Expired
        
        return license_data
        
    except Exception as e:
        print(f"License verification failed: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Offline License Generator")
    parser.add_argument("--hwid", required=True, help="Hardware fingerprint")
    parser.add_argument("--name", required=True, help="Customer name")
    parser.add_argument("--phone", default="", help="Customer phone")
    parser.add_argument("--days", type=int, help="License duration in days")
    parser.add_argument("--permanent", action="store_true", help="Permanent license")
    parser.add_argument("--max-users", type=int, default=1, help="Max users")
    parser.add_argument("--output", default=".", help="Output directory")
    
    args = parser.parse_args()
    
    if not args.permanent and not args.days:
        parser.error("Either --days or --permanent is required")
    
    generate_license_file(
        hwid=args.hwid,
        customer_name=args.name,
        customer_phone=args.phone,
        days=args.days if not args.permanent else None,
        max_users=args.max_users,
        output_dir=args.output,
    )


if __name__ == "__main__":
    main()
