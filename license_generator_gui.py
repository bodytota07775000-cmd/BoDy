"""
Offline License Generator - GUI Tool
Professional tool for generating license files.
"""
import hashlib
import json
import os
import secrets
import sys
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta
from pathlib import Path

# Secret key - CHANGE THIS!
SECRET_KEY = b"erp-offline-license-secret-2024"


def derive_key(hwid):
    return hashlib.pbkdf2_hmac("sha256", SECRET_KEY, hwid.encode(), 100000)


def xor_encrypt(data, key):
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def generate_license(hwid, name, phone, days, max_users, output_dir):
    import base64
    
    if days is not None:
        expiry = datetime.now() + timedelta(days=days)
        expiry_str = expiry.strftime("%Y-%m-%d")
    else:
        expiry_str = "permanent"
    
    license_data = {
        "v": 1,
        "hwid": hwid.upper(),
        "name": name,
        "phone": phone,
        "exp": expiry_str,
        "max": max_users,
        "feat": ["all"],
        "created": datetime.now().isoformat(),
        "id": secrets.token_hex(8),
    }
    
    data_str = json.dumps(license_data, separators=(",", ":"))
    data_bytes = data_str.encode("utf-8")
    
    key = derive_key(hwid)
    signature = hashlib.sha256(key + data_bytes + SECRET_KEY).hexdigest()[:32]
    encrypted = xor_encrypt(data_bytes, key)
    encoded = base64.urlsafe_b64encode(encrypted).decode()
    
    lic_content = f"ERPOFFLINE-1\n{hwid.upper()[:16]}\n{signature}\n{encoded}\n"
    
    safe_name = name.replace(" ", "_").replace("/", "_")
    output_path = Path(output_dir) / f"license_{safe_name}.lic"
    output_path.write_text(lic_content, encoding="utf-8")
    
    return output_path, license_data


class LicenseGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ERP License Generator")
        self.root.geometry("550x650")
        self.root.resizable(False, False)
        
        # Style
        style = ttk.Style()
        style.theme_use("clam")
        
        # Main frame
        main_frame = ttk.Frame(root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_frame = tk.Frame(main_frame, bg="#1e40af", height=60)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        title_frame.pack_propagate(False)
        tk.Label(title_frame, text="ERP License Generator", fg="white", bg="#1e40af", font=("Arial", 18, "bold")).pack(expand=True)
        
        # Customer Name
        ttk.Label(main_frame, text="Customer Name:", font=("Arial", 11)).pack(anchor=tk.W, pady=(5, 2))
        self.name_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.name_var, font=("Arial", 12), width=50).pack(fill=tk.X, pady=(0, 10))
        
        # Customer Phone
        ttk.Label(main_frame, text="Customer Phone:", font=("Arial", 11)).pack(anchor=tk.W, pady=(5, 2))
        self.phone_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.phone_var, font=("Arial", 12), width=50).pack(fill=tk.X, pady=(0, 10))
        
        # Hardware ID
        ttk.Label(main_frame, text="Hardware ID (HWID):", font=("Arial", 11)).pack(anchor=tk.W, pady=(5, 2))
        hwid_frame = ttk.Frame(main_frame)
        hwid_frame.pack(fill=tk.X, pady=(0, 10))
        self.hwid_var = tk.StringVar()
        ttk.Entry(hwid_frame, textvariable=self.hwid_var, font=("Courier", 11), width=40).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(hwid_frame, text="Paste", command=self.paste_hwid).pack(side=tk.RIGHT, padx=(5, 0))
        
        # License Type
        ttk.Label(main_frame, text="License Type:", font=("Arial", 11)).pack(anchor=tk.W, pady=(5, 2))
        self.type_var = tk.StringVar(value="days")
        type_frame = ttk.Frame(main_frame)
        type_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Radiobutton(type_frame, text="Timed", variable=self.type_var, value="days", command=self.toggle_days).pack(side=tk.LEFT)
        ttk.Radiobutton(type_frame, text="Permanent", variable=self.type_var, value="permanent", command=self.toggle_days).pack(side=tk.LEFT, padx=(20, 0))
        
        # Days
        self.days_frame = ttk.Frame(main_frame)
        self.days_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(self.days_frame, text="Duration (days):", font=("Arial", 11)).pack(side=tk.LEFT)
        self.days_var = tk.StringVar(value="365")
        ttk.Entry(self.days_frame, textvariable=self.days_var, font=("Arial", 12), width=10).pack(side=tk.LEFT, padx=(10, 0))
        
        # Max Users
        ttk.Label(main_frame, text="Max Users:", font=("Arial", 11)).pack(anchor=tk.W, pady=(5, 2))
        self.users_var = tk.StringVar(value="1")
        ttk.Entry(main_frame, textvariable=self.users_var, font=("Arial", 12), width=10).pack(anchor=tk.W, pady=(0, 10))
        
        # Output Dir
        ttk.Label(main_frame, text="Output Directory:", font=("Arial", 11)).pack(anchor=tk.W, pady=(5, 2))
        dir_frame = ttk.Frame(main_frame)
        dir_frame.pack(fill=tk.X, pady=(0, 15))
        self.dir_var = tk.StringVar(value=str(Path.home() / "Desktop"))
        ttk.Entry(dir_frame, textvariable=self.dir_var, font=("Arial", 11), width=40).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(dir_frame, text="Browse", command=self.browse_dir).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Generate Button
        generate_btn = tk.Button(main_frame, text="GENERATE LICENSE", bg="#1e40af", fg="white", font=("Arial", 14, "bold"), command=self.generate)
        generate_btn.pack(fill=tk.X, pady=(10, 5), ipady=8)
        
        # Result
        self.result_var = tk.StringVar()
        self.result_label = ttk.Label(main_frame, textvariable=self.result_var, font=("Arial", 10), foreground="green")
        self.result_label.pack(pady=(5, 0))
    
    def paste_hwid(self):
        try:
            self.hwid_var.set(self.root.clipboard_get().strip())
        except:
            pass
    
    def toggle_days(self):
        if self.type_var.get() == "days":
            for w in self.days_frame.winfo_children():
                w.configure(state="normal")
        else:
            for w in self.days_frame.winfo_children():
                if isinstance(w, ttk.Entry):
                    w.configure(state="disabled")
    
    def browse_dir(self):
        from tkinter import filedialog
        d = filedialog.askdirectory()
        if d:
            self.dir_var.set(d)
    
    def generate(self):
        name = self.name_var.get().strip()
        phone = self.phone_var.get().strip()
        hwid = self.hwid_var.get().strip()
        
        if not name:
            messagebox.showerror("Error", "Customer name is required")
            return
        if not hwid:
            messagebox.showerror("Error", "Hardware ID is required")
            return
        
        days = None
        if self.type_var.get() == "days":
            try:
                days = int(self.days_var.get())
            except:
                messagebox.showerror("Error", "Invalid days value")
                return
        
        try:
            max_users = int(self.users_var.get())
        except:
            max_users = 1
        
        output_dir = self.dir_var.get()
        os.makedirs(output_dir, exist_ok=True)
        
        try:
            path, data = generate_license(hwid, name, phone, days, max_users, output_dir)
            
            exp_text = data["exp"] if data["exp"] != "permanent" else "Permanent"
            self.result_var.set(f"Created: {path.name}\nExpiry: {exp_text}\nID: {data['id']}")
            messagebox.showinfo("Success", f"License file created!\n\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate license:\n{e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = LicenseGeneratorApp(root)
    root.mainloop()
