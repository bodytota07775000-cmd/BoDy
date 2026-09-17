"""License Manager Backend — professional license management tool."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Add parent directory to access license crypto
# Try local copy first, then fall back to backend directory
local_core = Path(__file__).resolve().parent / "app" / "core"
if local_core.exists():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "backend"))
from app.core.license_crypto import generate_license_key, validate_license_key, get_license_info
from app.core.fingerprint import get_hardware_fingerprint

app = FastAPI(title="License Manager")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# License database (JSON file)
LICENSE_DB = Path(__file__).parent / "licenses.json"


def load_licenses() -> list[dict]:
    """Load licenses from JSON file."""
    if LICENSE_DB.exists():
        with open(LICENSE_DB, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def save_licenses(licenses: list[dict]):
    """Save licenses to JSON file."""
    with open(LICENSE_DB, "w", encoding="utf-8") as f:
        json.dump(licenses, f, indent=2, ensure_ascii=False)


class LicenseCreate(BaseModel):
    fingerprint: str
    expires_at: str | None = None
    max_users: int = 1
    features: list[str] = ["all"]
    customer_name: str | None = None
    customer_phone: str | None = None
    notes: str | None = None


class LicenseResponse(BaseModel):
    id: int
    customer_name: str | None
    customer_phone: str | None
    fingerprint: str
    license_key: str
    expires_at: str | None
    max_users: int
    features: list[str]
    notes: str | None
    created_at: str
    is_active: bool


@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    """Serve the license manager dashboard."""
    dashboard_path = Path(__file__).parent / "static" / "index.html"
    return HTMLResponse(content=dashboard_path.read_text(encoding="utf-8"))


@app.get("/api/licenses")
def list_licenses():
    """List all licenses."""
    licenses = load_licenses()
    return licenses


@app.post("/api/licenses")
def create_license(req: LicenseCreate):
    """Generate a new license key."""
    licenses = load_licenses()

    # Parse expiry date
    expires_at = None
    if req.expires_at:
        try:
            expires_at = datetime.strptime(req.expires_at, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")

    # Generate license key
    key = generate_license_key(
        fingerprint=req.fingerprint,
        expires_at=expires_at,
        max_users=req.max_users,
        features=req.features,
    )

    # Create license record
    license_record = {
        "id": len(licenses) + 1,
        "customer_name": req.customer_name,
        "customer_phone": req.customer_phone,
        "fingerprint": req.fingerprint,
        "license_key": key,
        "expires_at": req.expires_at,
        "max_users": req.max_users,
        "features": req.features,
        "notes": req.notes,
        "created_at": datetime.now().isoformat(),
        "is_active": True,
    }

    licenses.append(license_record)
    save_licenses(licenses)

    return license_record


@app.delete("/api/licenses/{license_id}")
def delete_license(license_id: int):
    """Delete a license."""
    licenses = load_licenses()
    licenses = [l for l in licenses if l["id"] != license_id]
    save_licenses(licenses)
    return {"message": "License deleted"}


@app.patch("/api/licenses/{license_id}/toggle")
def toggle_license(license_id: int):
    """Toggle license active/inactive."""
    licenses = load_licenses()
    for lic in licenses:
        if lic["id"] == license_id:
            lic["is_active"] = not lic["is_active"]
            save_licenses(licenses)
            return lic
    raise HTTPException(status_code=404, detail="License not found")


@app.get("/api/licenses/{license_id}/verify")
def verify_license(license_id: int):
    """Verify a license key."""
    licenses = load_licenses()
    for lic in licenses:
        if lic["id"] == license_id:
            info = get_license_info(lic["license_key"])
            is_valid = validate_license_key(lic["license_key"], lic["fingerprint"]) is not None
            return {
                "is_valid": is_valid,
                "info": info,
                "license": lic,
            }
    raise HTTPException(status_code=404, detail="License not found")


@app.get("/api/stats")
def get_stats():
    """Get license statistics."""
    licenses = load_licenses()
    total = len(licenses)
    active = sum(1 for l in licenses if l.get("is_active", True))
    expired = 0
    now = datetime.now()
    for l in licenses:
        if l.get("expires_at"):
            try:
                exp = datetime.strptime(l["expires_at"], "%Y-%m-%d")
                if now > exp:
                    expired += 1
            except ValueError:
                pass

    return {
        "total": total,
        "active": active,
        "inactive": total - active,
        "expired": expired,
    }


@app.get("/api/fingerprint")
def get_fingerprint():
    """Get the local machine fingerprint."""
    return {"fingerprint": get_hardware_fingerprint()}


# Email Backup Configuration
EMAIL_CONFIG = {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "email": "",  # Will be set from frontend
    "app_password": "",  # Will be set from frontend
}


class EmailBackupRequest(BaseModel):
    email: str
    app_password: str


class EmailSendRequest(BaseModel):
    to_email: str
    subject: str
    body: str
    attachment_name: str | None = None
    attachment_content: str | None = None


def send_email(to_email: str, subject: str, body: str, 
               attachment_name: str | None = None, 
               attachment_content: str | None = None,
               email: str = None, app_password: str = None) -> bool:
    """Send email via Gmail SMTP."""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email.mime.base import MIMEBase
    from email import encoders
    
    sender = email or EMAIL_CONFIG.get("email")
    password = app_password or EMAIL_CONFIG.get("app_password")
    
    if not sender or not password:
        raise ValueError("Email credentials not configured")
    
    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = to_email
    msg["Subject"] = subject
    
    msg.attach(MIMEText(body, "html", "utf-8"))
    
    if attachment_name and attachment_content:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment_content.encode("utf-8"))
        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f"attachment; filename={attachment_name}",
        )
        msg.attach(part)
    
    with smtplib.SMTP(sender.split("@")[0] + ".smtp.com", 587) as server:
        server.starttls()
        server.login(sender, password)
        server.send_message(msg)
    
    return True


@app.post("/api/backup/email")
def send_backup_email(req: EmailBackupRequest):
    """Send license backup to email."""
    licenses = load_licenses()
    
    # Save credentials
    EMAIL_CONFIG["email"] = req.email
    EMAIL_CONFIG["app_password"] = req.app_password
    
    # Create backup content
    backup_data = {
        "export_date": datetime.now().isoformat(),
        "total_licenses": len(licenses),
        "licenses": licenses,
    }
    
    # Create email body
    html_body = f"""
    <html dir="rtl">
    <head><meta charset="UTF-8"></head>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #1e40af;">License Manager Backup</h2>
        <p><strong>تاريخ النسخة الاحتياطية:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>إجمالي التراخيص:</strong> {len(licenses)}</p>
        <hr>
        <h3>الترخيصات:</h3>
    """
    
    for lic in licenses:
        status = "نشط" if lic.get("is_active", True) else "معطل"
        html_body += f"""
        <div style="border: 1px solid #ddd; padding: 10px; margin: 10px 0; border-radius: 8px;">
            <p><strong>العميل:</strong> {lic.get('customer_name', '—')}</p>
            <p><strong>البصمة:</strong> <code>{lic.get('fingerprint', '')[:32]}...</code></p>
            <p><strong>المفتاح:</strong> <code style="color: #1e40af;">{lic.get('license_key', '')[:50]}...</code></p>
            <p><strong>الحالة:</strong> {status}</p>
            <p><strong>الانتهاء:</strong> {lic.get('expires_at', 'دائم')}</p>
        </div>
        """
    
    html_body += """
        <hr>
        <p style="color: #666; font-size: 12px;">
            هذه رسالة تلقائية من License Manager.<br>
            للرجوع للبرنامج، افتح: <a href="http://localhost:8001">License Manager</a>
        </p>
    </body>
    </html>
    """
    
    # Send email
    try:
        send_email(
            to_email=req.email,
            subject=f"License Manager Backup - {datetime.now().strftime('%Y-%m-%d')}",
            body=html_body,
            attachment_name="licenses_backup.json",
            attachment_content=json.dumps(backup_data, indent=2, ensure_ascii=False),
            email=req.email,
            app_password=req.app_password,
        )
        return {"message": "تم إرسال النسخة الاحتياطية بنجاح"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"فشل الإرسال: {str(e)}")


@app.post("/api/backup/download")
def download_backup():
    """Download backup as JSON file."""
    licenses = load_licenses()
    backup_data = {
        "export_date": datetime.now().isoformat(),
        "total_licenses": len(licenses),
        "licenses": licenses,
    }
    return JSONResponse(
        content=backup_data,
        headers={
            "Content-Disposition": f"attachment; filename=licenses_backup_{datetime.now().strftime('%Y%m%d')}.json"
        },
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
