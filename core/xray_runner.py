"""
Xray-Core Integration, RealDelay Tester & Configuration Generator
Handles:
- Generating Xray client JSON configs with clean IP override
- Downloading & managing official Xray-core binary (Windows, Linux, macOS)
- Running high-concurrency RealDelay testing through Xray proxy inbounds
"""

import asyncio
import json
import logging
import os
import platform
import shutil
import socket
import stat
import subprocess
import sys
import time
import urllib.request
import zipfile
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.config_parser import ConfigParser, ParsedConfig

logger = logging.getLogger(__name__)

BASE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN_DIR = os.path.join(BASE_DIR, "bin")
USER_BIN_DIR = os.path.join(os.path.expanduser("~"), ".cf_scanner", "bin")


def get_free_port() -> int:
    """Finds an available free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class XrayManager:
    """Manages official Xray-core executable for the current OS."""

    @staticmethod
    def get_xray_binary_name() -> str:
        return "xray.exe" if platform.system() == "Windows" else "xray"

    @staticmethod
    def get_xray_path() -> str:
        binary_name = XrayManager.get_xray_binary_name()
        # 1. Check local/bundled bin directory
        local_path = os.path.join(BIN_DIR, binary_name)
        if os.path.exists(local_path):
            return local_path

        # 2. Check user app data directory
        user_path = os.path.join(USER_BIN_DIR, binary_name)
        if os.path.exists(user_path):
            return user_path

        # 3. Check system PATH
        system_path = shutil.which(binary_name) or shutil.which("xray")
        if system_path:
            return system_path

        return user_path if not os.access(BIN_DIR, os.W_OK) else local_path

    @staticmethod
    def is_xray_available() -> bool:
        path = XrayManager.get_xray_path()
        return os.path.exists(path) and os.path.isfile(path)

    @staticmethod
    def download_xray() -> Tuple[bool, str]:
        """
        Downloads latest official Xray-core release from GitHub for current OS & architecture.
        """
        os.makedirs(BIN_DIR, exist_ok=True)
        sys_name = platform.system().lower()
        machine = platform.machine().lower()

        # Map architecture
        if "arm" in machine or "aarch64" in machine:
            arch = "arm64-v8a"
        elif "64" in machine or "amd64" in machine or "x86_64" in machine:
            arch = "64"
        else:
            arch = "32"

        if sys_name == "windows":
            zip_name = f"Xray-windows-{arch}.zip"
        elif sys_name == "darwin":
            zip_name = f"Xray-macos-{arch}.zip"
        elif sys_name == "linux":
            zip_name = f"Xray-linux-{arch}.zip"
        else:
            return False, f"Unsupported OS: {sys_name}"

        url = f"https://github.com/XTLS/Xray-core/releases/latest/download/{zip_name}"
        zip_dest = os.path.join(BIN_DIR, zip_name)

        try:
            logger.info(f"Downloading Xray-core from {url} ...")
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as resp, open(zip_dest, "wb") as out_file:
                shutil.copyfileobj(resp, out_file)

            with zipfile.ZipFile(zip_dest, "r") as zip_ref:
                zip_ref.extractall(BIN_DIR)

            if os.path.exists(zip_dest):
                os.remove(zip_dest)

            # Make binary executable on Linux/macOS
            bin_path = XrayManager.get_xray_path()
            if os.path.exists(bin_path) and sys_name != "windows":
                st = os.stat(bin_path)
                os.chmod(bin_path, st.st_mode | stat.S_IEXEC)

            return True, bin_path
        except Exception as e:
            logger.error(f"Failed to download Xray-core: {e}")
            return False, str(e)

    @staticmethod
    def generate_xray_config(
        parsed: ParsedConfig,
        clean_ip: str,
        inbound_socks_port: int,
        inbound_http_port: int
    ) -> Dict[str, Any]:
        """
        Generates an Xray client JSON configuration structure pointing to clean_ip.
        """
        sni = parsed.get_sni_or_host()
        host = parsed.get_host_header()
        raw_path = parsed.path or "/"
        if not raw_path.startswith("/"):
            raw_path = "/" + raw_path

        # StreamSettings
        transport = parsed.transport.lower()
        if transport in ["xhttp", "splithttp"]:
            network = "xhttp"
        elif transport in ["grpc", "ws", "httpupgrade", "tcp"]:
            network = transport
        else:
            network = "ws"

        stream_settings: Dict[str, Any] = {
            "network": network,
            "security": parsed.security if parsed.security in ["tls", "reality"] else "none",
        }

        if parsed.security in ["tls", "reality"]:
            tls_settings: Dict[str, Any] = {
                "serverName": sni,
            }
            if parsed.alpn:
                alpn_list = [a.strip() for a in parsed.alpn.split(",") if a.strip()]
                tls_settings["alpn"] = alpn_list if alpn_list else ["h2", "http/1.1"]
            else:
                tls_settings["alpn"] = ["h2", "http/1.1"]

            if parsed.fingerprint:
                tls_settings["fingerprint"] = parsed.fingerprint

            if parsed.security == "reality":
                stream_settings["realitySettings"] = tls_settings
            else:
                stream_settings["tlsSettings"] = tls_settings

        # Transport specific settings
        if network == "xhttp":
            xhttp_obj: Dict[str, Any] = {
                "path": raw_path,
                "host": host,
                "mode": parsed.mode or "packet-up"
            }
            if parsed.extra and isinstance(parsed.extra, dict):
                for k, v in parsed.extra.items():
                    if k == "headers" and isinstance(v, dict):
                        cleaned_headers = {}
                        for hk, hv in v.items():
                            if isinstance(hv, str):
                                cleaned_headers[hk] = urllib.parse.unquote_plus(hv)
                            else:
                                cleaned_headers[hk] = hv
                        xhttp_obj["headers"] = cleaned_headers
                    else:
                        xhttp_obj[k] = v
            stream_settings["xhttpSettings"] = xhttp_obj
        elif network == "ws":
            ws_headers: Dict[str, str] = {"Host": host}
            if parsed.extra and isinstance(parsed.extra, dict) and "headers" in parsed.extra:
                if isinstance(parsed.extra["headers"], dict):
                    for hk, hv in parsed.extra["headers"].items():
                        ws_headers[hk] = urllib.parse.unquote_plus(hv) if isinstance(hv, str) else str(hv)
            stream_settings["wsSettings"] = {
                "path": raw_path,
                "headers": ws_headers
            }
        elif network == "grpc":
            stream_settings["grpcSettings"] = {
                "serviceName": raw_path.lstrip("/")
            }
        elif network == "httpupgrade":
            stream_settings["httpupgradeSettings"] = {
                "path": raw_path,
                "host": host
            }

        # Outbound protocol settings
        outbound_settings: Dict[str, Any] = {}
        encryption_val = parsed.encryption if parsed.encryption and parsed.encryption != "none" else "none"

        if parsed.protocol == "vless":
            outbound_settings = {
                "vnext": [{
                    "address": clean_ip,
                    "port": parsed.port,
                    "users": [{
                        "id": parsed.uuid,
                        "encryption": encryption_val,
                        "flow": parsed.flow or ""
                    }]
                }]
            }
        elif parsed.protocol == "vmess":
            outbound_settings = {
                "vnext": [{
                    "address": clean_ip,
                    "port": parsed.port,
                    "users": [{
                        "id": parsed.uuid,
                        "alterId": 0,
                        "security": "auto"
                    }]
                }]
            }
        elif parsed.protocol == "trojan":
            outbound_settings = {
                "servers": [{
                    "address": clean_ip,
                    "port": parsed.port,
                    "password": parsed.uuid
                }]
            }
        else:
            outbound_settings = {
                "vnext": [{
                    "address": clean_ip,
                    "port": parsed.port,
                    "users": [{"id": parsed.uuid or "11111111-2222-3333-4444-555555555555", "encryption": "none"}]
                }]
            }

        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "tag": "socks-in",
                    "port": inbound_socks_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True}
                },
                {
                    "tag": "http-in",
                    "port": inbound_http_port,
                    "listen": "127.0.0.1",
                    "protocol": "http",
                    "settings": {"allowTransparent": False}
                }
            ],
            "outbounds": [
                {
                    "tag": "proxy",
                    "protocol": parsed.protocol if parsed.protocol in ["vless", "vmess", "trojan"] else "vless",
                    "settings": outbound_settings,
                    "streamSettings": stream_settings
                },
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {}
                }
            ]
        }
        return config


class XrayTester:
    """Runs RealDelay tests through Xray-core proxy instances."""

    @staticmethod
    async def test_single_realdelay(
        parsed: ParsedConfig,
        clean_ip: str,
        timeout_sec: float = 3.5,
        target_url: str = "http://connectivitycheck.gstatic.com/generate_204"
    ) -> Dict[str, Any]:
        """
        Executes a real proxy delay test on clean_ip using Xray-core.
        """
        xray_bin = XrayManager.get_xray_path()
        if not os.path.exists(xray_bin):
            return {"status": "ERROR", "realdelay_ms": 0, "error": "Xray binary not found"}

        p_socks = get_free_port()
        p_http = get_free_port()

        config_dict = XrayManager.generate_xray_config(
            parsed=parsed,
            clean_ip=clean_ip,
            inbound_socks_port=p_socks,
            inbound_http_port=p_http
        )

        tmp_dir = BIN_DIR if os.path.exists(BIN_DIR) and os.access(BIN_DIR, os.W_OK) else os.path.expanduser("~")
        tmp_cfg_path = os.path.join(tmp_dir, f"xray_tmp_{p_http}_{int(time.time()*1000)%100000}.json")
        with open(tmp_cfg_path, "w", encoding="utf-8") as f:
            json.dump(config_dict, f)

        proc = None
        try:
            # Start Xray process
            proc = subprocess.Popen(
                [xray_bin, "run", "-c", tmp_cfg_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            # Give Xray time to initialize and bind
            await asyncio.sleep(0.4)

            # Test proxy request
            import urllib.request
            proxy_handler = urllib.request.ProxyHandler({
                "http": f"http://127.0.0.1:{p_http}",
                "https": f"http://127.0.0.1:{p_http}",
            })
            opener = urllib.request.build_opener(proxy_handler)
            req = urllib.request.Request(target_url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})

            def fetch():
                t0 = time.perf_counter()
                with opener.open(req, timeout=timeout_sec) as resp:
                    delay = (time.perf_counter() - t0) * 1000
                    return resp.status, delay

            loop = asyncio.get_running_loop()
            status_code, delay_ms = await loop.run_in_executor(None, fetch)

            return {
                "status": "SUCCESS" if status_code in [200, 204] else "FAILED",
                "realdelay_ms": round(delay_ms, 1),
                "http_code": status_code,
                "real_status": f"{status_code} RealDelay OK" if status_code in [200, 204] else f"HTTP {status_code}"
            }

        except Exception as e:
            return {"status": "FAILED", "realdelay_ms": 0, "error": str(e)}
        finally:
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=0.6)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            if os.path.exists(tmp_cfg_path):
                try:
                    os.remove(tmp_cfg_path)
                except Exception:
                    pass
            if os.path.exists(tmp_cfg_path):
                try:
                    os.remove(tmp_cfg_path)
                except Exception:
                    pass
