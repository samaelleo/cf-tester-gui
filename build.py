"""
Cross-Platform PyInstaller Builder for Cloudflare Clean IP Scanner
Generates standalone binaries for Windows (.exe), Linux, and macOS.
"""

import os
import platform
import subprocess
import sys


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
        "--hidden-import", "engineio.async_drivers.threading",
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
        print("[-] Build failed!")
        sys.exit(res.returncode)

    print(f"[✓] Build succeeded for {system}!")


if __name__ == "__main__":
    main()
