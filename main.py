"""
Cloudflare Clean IP Scanner - Cross-Platform Application Launcher
Supports Windows, macOS, and Linux (Native GUI Window, Browser Mode, or Headless Server).
"""

import argparse
import logging
import os
import platform
import signal
import socket
import sys
import threading
import time
import webbrowser
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("cf_scanner")


def get_platform_name() -> str:
    """Returns 'Windows', 'macOS', 'Linux', or 'Unknown'."""
    sys_name = platform.system()
    if sys_name == "Windows":
        return "Windows"
    elif sys_name == "Darwin":
        return "macOS"
    elif sys_name == "Linux":
        return "Linux"
    return sys_name


def find_free_port(start_port: int = 58282) -> int:
    """Finds an available TCP port starting from start_port."""
    for port in range(start_port, start_port + 200):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return start_port


def wait_for_server(url: str, timeout: float = 8.0) -> bool:
    """Wait until the Flask server is responding."""
    import urllib.request
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=0.8) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.15)
    return False


def start_native_window(server_url: str, os_name: str) -> bool:
    """Attempts to launch a native desktop window using pywebview."""
    try:
        import webview

        # Select GUI backend based on OS
        gui_backend = None
        if os_name == "Windows":
            gui_backend = "edgechromium"
        elif os_name == "macOS":
            gui_backend = "cocoa"
        elif os_name == "Linux":
            # Check if DISPLAY or WAYLAND_DISPLAY is present
            if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
                logger.info("No DISPLAY or WAYLAND server detected on Linux. Falling back to browser/server mode.")
                return False
            gui_backend = "gtk"

        logger.info(f"Opening native desktop window on {os_name} (backend={gui_backend or 'auto'})...")
        window = webview.create_window(
            title="Cloudflare Clean IP Scanner | اسکنر آی‌پی تمیز کلادفلر (HE BGP)",
            url=server_url,
            width=1200,
            height=740,
            min_size=(880, 560),
            background_color="#070a12",
            text_select=True,
            confirm_close=False
        )

        webview.start(gui=gui_backend, debug=False)
        return True
    except Exception as e:
        logger.warning(f"Native desktop window launch not available on {os_name} ({e}).")
        return False


def main():
    parser = argparse.ArgumentParser(description="Cloudflare Clean IP Scanner (Cross-Platform)")
    parser.add_argument("--port", type=int, default=None, help="Port to run web server on (default: auto)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address to bind to (default: 127.0.0.1)")
    parser.add_argument("--headless", "--no-gui", action="store_true", help="Run as headless server without opening window or browser")
    parser.add_argument("--browser", action="store_true", help="Force opening in default web browser instead of native window")
    args = parser.parse_args()

    # Set working directory to project root
    base_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(base_dir)

    os_name = get_platform_name()
    port = args.port or find_free_port(58282)
    host = args.host
    server_url = f"http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port}"

    from app_server import app

    # Suppress Flask default banners in production mode
    import logging as py_logging
    py_logging.getLogger("werkzeug").setLevel(py_logging.ERROR)

    # Start Flask server in background daemon thread
    server_thread = threading.Thread(
        target=lambda: app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True),
        daemon=True
    )
    server_thread.start()

    logger.info(f"Checking server availability at {server_url} ...")
    if not wait_for_server(f"http://127.0.0.1:{port}"):
        logger.warning("Server initialization is taking longer than expected.")

    print(f"\n" + "=" * 64)
    print(f"  🚀 Cloudflare Clean IP Scanner is LIVE!")
    print(f"  💻 Platform: {os_name}")
    print(f"  🌐 URL:      {server_url}")
    print(f"=" * 64 + "\n")

    # Headless server mode (e.g. Linux VPS / Docker / Remote SSH)
    if args.headless:
        print("Running in headless server mode. Press Ctrl+C to terminate.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down scanner server...")
            sys.exit(0)

    # Browser only mode
    if args.browser:
        logger.info(f"Opening browser at {server_url} ...")
        webbrowser.open(server_url)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down scanner server...")
            sys.exit(0)

    # Attempt native desktop window first
    launched_native = start_native_window(server_url, os_name)

    # If native window closed or failed to initialize, fallback to browser
    if not launched_native:
        logger.info("Opening default system browser...")
        webbrowser.open(server_url)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down scanner server...")
            sys.exit(0)


if __name__ == "__main__":
    main()
