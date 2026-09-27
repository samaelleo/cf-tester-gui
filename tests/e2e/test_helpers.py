"""
Shared Test Helpers, Reference Oracles, and Capability Detectors for E2E Tests
"""

import base64
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.config_parser import ConfigParser, ParsedConfig
from core.bgp_fetcher import BGPFetcher
from core.tester_engine import TesterEngine, ScanResult
from core.xray_runner import XrayManager, XrayTester


# ==============================================================================
# 1. Authoritative Reference Oracles & Standards
# ==============================================================================

REFERENCE_CLOUDFLARE_V4_CIDRS = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

REFERENCE_CLOUDFLARE_V6_CIDRS = [
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
]

# Standard Test URIs across all protocols
SAMPLE_VLESS_WS = (
    "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@myworker.workers.dev:443"
    "?type=ws&security=tls&path=%2F%3Fed%3D2560&host=myworker.workers.dev"
    "&sni=myworker.workers.dev&fp=chrome#VLESS-WS-Node"
)

SAMPLE_VLESS_XHTTP_PQ = (
    "vless://937afff8-7513-4078-a759-b884b6c2d2ef@203.23.106.70:8443"
    "?encryption=mlkem768x25519plus.xorpub.0rtt.Hfz68R2EM_t2U26EoytKVZZv3I2kxQApYvNh2LXEASg"
    "&security=tls&sni=cf2.persiana.garden&fp=chrome&alpn=h2%2Chttp%2F1.1&insecure=0"
    "&type=xhttp&host=cf.persiana.garden&path=api%2Fv1%2Ftelemetry%2Fmetrics&mode=packet-up"
    "&extra=%7B%22headers%22%3A%7B%22Accept-Encoding%22%3A%22gzip%22%7D%2C%22mode%22%3A%22packet-up%22%7D#PQ-Node"
)

SAMPLE_VMESS_DICT = {
    "v": "2",
    "ps": "VMess-Test",
    "add": "orig.domain.com",
    "port": "443",
    "id": "11111111-2222-3333-4444-555555555555",
    "net": "ws",
    "type": "none",
    "host": "orig.domain.com",
    "path": "/vmessws",
    "tls": "tls",
    "sni": "orig.domain.com"
}
SAMPLE_VMESS = "vmess://" + base64.b64encode(json.dumps(SAMPLE_VMESS_DICT).encode()).decode()

SAMPLE_TROJAN = "trojan://mypassword123@trojan.domain.com:443?security=tls&sni=trojan.domain.com&type=ws&path=%2Ftr#TrojanTest"

SAMPLE_SS_PLAIN = "ss://aes-256-gcm:mySecretPass123@orig.domain.com:8443#SS-Plain-Node"
SAMPLE_SS_SIP002 = "ss://" + base64.b64encode(b"aes-256-gcm:mySecretPass123").decode() + "@orig.domain.com:8443#SS-SIP002-Node"
SAMPLE_SS_LEGACY = "ss://" + base64.b64encode(b"aes-256-gcm:mySecretPass123@orig.domain.com:8443").decode() + "#SS-Legacy-Node"
SAMPLE_SS_CHACHA = "ss://" + base64.b64encode(b"chacha20-ietf-poly1305:ultraSecureP@ss!").decode() + "@orig.domain.com:443#SS-ChaCha"

SAMPLE_DIRECT = "cf-direct.cloudflare.com:443/cdn-cgi/trace"


# ==============================================================================
# 2. Dynamic Capability and Milestone Detectors
# ==============================================================================

def is_desktop_ss_xray_implemented() -> bool:
    """Check if Shadowsocks outbound generation is implemented in core/xray_runner.py."""
    try:
        parsed = ConfigParser.parse(SAMPLE_SS_SIP002)
        cfg = XrayManager.generate_xray_config(parsed, "104.16.24.1", 10808, 10809)
        proxy_outbound = next((o for o in cfg.get("outbounds", []) if o.get("tag") == "proxy"), {})
        return proxy_outbound.get("protocol") == "shadowsocks"
    except Exception:
        return False


def is_desktop_cleanup_implemented() -> bool:
    """Check if duplicate cleanup code in core/xray_runner.py has been resolved."""
    xray_runner_path = os.path.join(PROJECT_ROOT, "core", "xray_runner.py")
    if not os.path.exists(xray_runner_path):
        return False
    with open(xray_runner_path, "r", encoding="utf-8") as f:
        content = f.read()
    # Check if duplicate cleanup block occurs only once
    pattern = r"if os\.path\.exists\(tmp_cfg_path\):\s*try:\s*os\.remove\(tmp_cfg_path\)"
    matches = len(re.findall(pattern, content))
    return matches == 1


def is_desktop_ipv6_implemented() -> bool:
    """Check if IPv6 fallback CIDRs or candidate generation is implemented."""
    bgp_fetcher_path = os.path.join(PROJECT_ROOT, "core", "bgp_fetcher.py")
    if not os.path.exists(bgp_fetcher_path):
        return False
    with open(bgp_fetcher_path, "r", encoding="utf-8") as f:
        content = f.read()
    return "FALLBACK_CLOUDFLARE_V6" in content or "2606:4700::" in content


def is_android_gradle_setup_implemented() -> bool:
    """Check if android/ Gradle project files exist."""
    return os.path.exists(os.path.join(PROJECT_ROOT, "android", "settings.gradle.kts")) or \
           os.path.exists(os.path.join(PROJECT_ROOT, "android", "settings.gradle"))


def is_android_manifest_implemented() -> bool:
    """Check if AndroidManifest.xml exists."""
    manifest_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "AndroidManifest.xml")
    return os.path.exists(manifest_path)


def is_android_core_implemented() -> bool:
    """Check if Android Kotlin core files exist."""
    kt_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core")
    return os.path.exists(kt_path)


def is_android_xray_jni_implemented() -> bool:
    """Check if Android Xray JNI / download script exists."""
    script_path = os.path.join(PROJECT_ROOT, "scripts", "download_xray_android.py")
    jni_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "jniLibs")
    return os.path.exists(script_path) or os.path.exists(jni_path)


def is_android_service_implemented() -> bool:
    """Check if Android Foreground Service exists."""
    srv_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "service")
    return os.path.exists(srv_path)


def is_android_compose_ui_implemented() -> bool:
    """Check if Jetpack Compose UI files exist."""
    ui_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "ui")
    return os.path.exists(ui_path)


def is_android_jvm_tests_implemented() -> bool:
    """Check if Android JVM unit test files exist."""
    test_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "test")
    return os.path.exists(test_path)


def is_cicd_android_release_implemented() -> bool:
    """Check if .github/workflows/release.yml contains build-android job."""
    workflow_path = os.path.join(PROJECT_ROOT, ".github", "workflows", "release.yml")
    if not os.path.exists(workflow_path):
        return False
    with open(workflow_path, "r", encoding="utf-8") as f:
        content = f.read()
    return "build-android" in content


# ==============================================================================
# 3. Verification & Extraction Helpers
# ==============================================================================

def extract_ss_credentials(uuid_or_userinfo: str) -> tuple[str, str]:
    """
    Extracts (method, password) from Shadowsocks userinfo.
    Handles plain 'method:password' or Base64 encoded SIP002 credentials.
    """
    raw = uuid_or_userinfo.strip()
    if ":" in raw:
        parts = raw.split(":", 1)
        return parts[0].strip(), parts[1].strip()
    
    # Try Base64 decoding
    try:
        padding = len(raw) % 4
        if padding:
            raw_padded = raw + ("=" * (4 - padding))
        else:
            raw_padded = raw
        decoded = base64.b64decode(raw_padded).decode("utf-8", errors="ignore")
        if ":" in decoded:
            parts = decoded.split(":", 1)
            return parts[0].strip(), parts[1].strip()
    except Exception:
        pass
    return "aes-256-gcm", raw


def format_clean_ip_url(clean_ip: str, port: int) -> str:
    """Formats host:port string with RFC 3986 bracket notation for IPv6."""
    clean_ip = clean_ip.strip()
    if ":" in clean_ip and not clean_ip.startswith("["):
        return f"[{clean_ip}]:{port}"
    return f"{clean_ip}:{port}"
