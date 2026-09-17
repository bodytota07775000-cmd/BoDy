"""Hardware fingerprint collection — ties license to a specific machine.

Collects unique hardware identifiers and generates a stable SHA-256 hash.
Works on Windows, Linux, and macOS.
"""
from __future__ import annotations

import hashlib
import platform
import subprocess
import uuid


def _get_windows_machine_guid() -> str:
    """Read Windows MachineGuid from registry."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
        )
        value, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return str(value)
    except Exception:
        return ""


def _get_linux_machine_id() -> str:
    """Read /etc/machine-id on Linux."""
    try:
        with open("/etc/machine-id", "r") as f:
            return f.read().strip()
    except Exception:
        return ""


def _get_mac_address() -> str:
    """Get the primary MAC address."""
    mac = uuid.getnode()
    return ":".join(f"{(mac >> i) & 0xFF:02x}" for i in range(0, 48, 8))


def _get_cpu_id() -> str:
    """Get CPU identifier."""
    system = platform.system()
    try:
        if system == "Windows":
            result = subprocess.run(
                ["wmic", "cpu", "get", "ProcessorId"],
                capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.strip().split("\n")
            if len(lines) > 1:
                return lines[1].strip()
        elif system == "Linux":
            result = subprocess.run(
                ["lscpu"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split("\n"):
                if "Model name" in line:
                    return line.split(":")[-1].strip()
        elif system == "Darwin":
            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip()
    except Exception:
        pass
    return platform.processor() or ""


def _get_disk_serial() -> str:
    """Get primary disk serial number."""
    system = platform.system()
    try:
        if system == "Windows":
            result = subprocess.run(
                ["wmic", "diskdrive", "get", "SerialNumber"],
                capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.strip().split("\n")
            if len(lines) > 1:
                serial = lines[1].strip()
                if serial and serial != "SerialNumber":
                    return serial
        elif system == "Linux":
            result = subprocess.run(
                ["lsblk", "-dno", "SERIAL", "/dev/sda"],
                capture_output=True, text=True, timeout=10
            )
            serial = result.stdout.strip()
            if serial:
                return serial
            # Fallback: try /sys
            with open("/sys/block/sda/device/serial", "r") as f:
                return f.read().strip()
    except Exception:
        pass
    return ""


def get_hardware_fingerprint() -> str:
    """Generate a stable hardware fingerprint hash.

    Combines multiple hardware identifiers into a single SHA-256 hash.
    The same machine will always produce the same fingerprint.
    """
    components = [
        _get_windows_machine_guid(),
        _get_linux_machine_id(),
        _get_mac_address(),
        _get_cpu_id(),
        _get_disk_serial(),
        platform.system(),
        platform.machine(),
    ]

    combined = "|".join(components)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    fp = get_hardware_fingerprint()
    print(f"Fingerprint: {fp}")
