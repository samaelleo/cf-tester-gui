"""
Cross-Platform PyInstaller Builder for Cloudflare Clean IP Scanner
Generates standalone binaries for Windows (.exe), Linux, and macOS.
"""

import os
import platform
import subprocess
import sys

# Ensure UTF-8 output encoding on all terminals/runners
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def main():
    system = platform.system()
    sep = ";" if system == "Windows" else ":"

    print(f"[*] Building Cloudflare Clean IP Scanner for {system} ({platform.machine()})...")

    # PyInstaller arguments
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--name", "cf-clean-ip-scanner",
        "--add-data", f"ui{sep}ui",
        "--hidden-import", "jinja2",
        "--hidden-import", "werkzeug",
        "--hidden-import", "flask",
        "--hidden-import", "aiohttp",
        "--hidden-import", "requests",
        "--hidden-import", "webview",
    ]

    if system == "Windows":
        cmd.extend([
            "--onefile",
            "--console",  # Allows seeing logs and CLI arguments
        ])
    elif system == "Darwin":  # macOS
        cmd.extend([
            "--windowed",
            "--onedir",
            "--osx-bundle-identifier", "com.cfscanner.app",
        ])
    else:  # Linux
        cmd.extend([
            "--onefile",
        ])

    cmd.append("main.py")

    print(f"[+] Running: {' '.join(cmd)}")
    res = subprocess.run(cmd)
    if res.returncode != 0:
        print("[-] Build failed with exit code:", res.returncode)
        sys.exit(res.returncode)

    print(f"[OK] Build succeeded for {system}!")


if __name__ == "__main__":
    main()
