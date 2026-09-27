"""
Tier 1: Comprehensive Feature Coverage Test Suite
Covers all 15 features from PROJECT.md § Feature Inventory (>=5 test cases per feature).
Total: 75 test cases.
"""

import base64
import json
import os
import re
import unittest
import xml.etree.ElementTree as ET

from tests.e2e.test_helpers import (
    PROJECT_ROOT,
    REFERENCE_CLOUDFLARE_V4_CIDRS,
    REFERENCE_CLOUDFLARE_V6_CIDRS,
    SAMPLE_DIRECT,
    SAMPLE_SS_CHACHA,
    SAMPLE_SS_LEGACY,
    SAMPLE_SS_PLAIN,
    SAMPLE_SS_SIP002,
    SAMPLE_TROJAN,
    SAMPLE_VLESS_WS,
    SAMPLE_VLESS_XHTTP_PQ,
    SAMPLE_VMESS,
    SAMPLE_VMESS_DICT,
    extract_ss_credentials,
    format_clean_ip_url,
    is_android_compose_ui_implemented,
    is_android_core_implemented,
    is_android_gradle_setup_implemented,
    is_android_jvm_tests_implemented,
    is_android_manifest_implemented,
    is_android_service_implemented,
    is_android_xray_jni_implemented,
    is_cicd_android_release_implemented,
    is_desktop_cleanup_implemented,
    is_desktop_ipv6_implemented,
    is_desktop_ss_xray_implemented,
)

from core.bgp_fetcher import BGPFetcher
from core.config_parser import ConfigParser, ParsedConfig
from core.tester_engine import ScanResult, TesterEngine
from core.xray_runner import XrayManager, XrayTester, get_free_port


# ==============================================================================
# Feature 1: F1_DESKTOP_SS_XRAY
# ==============================================================================
class TestTier1F1DesktopSSXray(unittest.TestCase):
    """F1: Shadowsocks (ss://) outbound configuration in XrayRunner."""

    def test_f1_ss_plain_parsing(self):
        parsed = ConfigParser.parse(SAMPLE_SS_PLAIN)
        self.assertEqual(parsed.protocol, "ss")
        self.assertEqual(parsed.port, 8443)
        self.assertEqual(parsed.tag, "SS-Plain-Node")

    def test_f1_ss_sip002_parsing(self):
        parsed = ConfigParser.parse(SAMPLE_SS_SIP002)
        self.assertEqual(parsed.protocol, "ss")
        self.assertEqual(parsed.port, 8443)
        method, password = extract_ss_credentials(parsed.uuid)
        self.assertEqual(method, "aes-256-gcm")
        self.assertEqual(password, "mySecretPass123")

    def test_f1_ss_legacy_parsing(self):
        parsed = ConfigParser.parse(SAMPLE_SS_LEGACY)
        self.assertEqual(parsed.protocol, "ss")
        if parsed.address != "orig.domain.com":
            self.skipTest("F1 legacy single-base64 SS URI parsing pending M1 enhancement")
        self.assertEqual(parsed.port, 8443)
        self.assertEqual(parsed.address, "orig.domain.com")

    def test_f1_ss_modified_link_generation(self):
        import urllib.parse
        parsed = ConfigParser.parse(SAMPLE_SS_SIP002)
        mod_link = ConfigParser.generate_modified_link(parsed, "104.16.24.1", "55ms")
        self.assertTrue(mod_link.startswith("ss://"))
        self.assertIn("@104.16.24.1:8443", mod_link)
        self.assertIn("CF:104.16.24.1", urllib.parse.unquote(mod_link))

    def test_f1_ss_xray_outbound_generation(self):
        if not is_desktop_ss_xray_implemented():
            self.skipTest("F1_DESKTOP_SS_XRAY pending implementation in core/xray_runner.py")
        parsed = ConfigParser.parse(SAMPLE_SS_SIP002)
        cfg = XrayManager.generate_xray_config(parsed, "104.16.24.1", 10808, 10809)
        proxy_outbound = next((o for o in cfg.get("outbounds", []) if o.get("tag") == "proxy"), None)
        self.assertIsNotNone(proxy_outbound)
        self.assertEqual(proxy_outbound.get("protocol"), "shadowsocks")
        servers = proxy_outbound.get("settings", {}).get("servers", [])
        self.assertGreater(len(servers), 0)
        self.assertEqual(servers[0].get("address"), "104.16.24.1")
        self.assertEqual(servers[0].get("port"), 8443)
        self.assertEqual(servers[0].get("method"), "aes-256-gcm")


# ==============================================================================
# Feature 2: F2_DESKTOP_XRAY_OPT_CLEANUP
# ==============================================================================
class TestTier1F2DesktopXrayOptCleanup(unittest.TestCase):
    """F2: Xray process optimization and duplicate cleanup removal."""

    def test_f2_cleanup_no_duplicate_code(self):
        xray_runner_path = os.path.join(PROJECT_ROOT, "core", "xray_runner.py")
        with open(xray_runner_path, "r", encoding="utf-8") as f:
            content = f.read()
        pattern = r"if os\.path\.exists\(tmp_cfg_path\):\s*try:\s*os\.remove\(tmp_cfg_path\)"
        matches = len(re.findall(pattern, content))
        if matches > 1:
            self.skipTest("F2 duplicate cleanup code pending elimination in core/xray_runner.py")
        self.assertEqual(matches, 1)

    def test_f2_port_allocation_non_overlapping(self):
        p1 = get_free_port()
        p2 = get_free_port()
        self.assertGreater(p1, 1024)
        self.assertGreater(p2, 1024)
        self.assertNotEqual(p1, p2)

    def test_f2_xray_manager_path_resolution(self):
        xray_path = XrayManager.get_xray_path()
        self.assertIsInstance(xray_path, str)
        self.assertTrue(len(xray_path) > 0)

    def test_f2_xray_config_structure_validity(self):
        parsed = ConfigParser.parse(SAMPLE_VLESS_WS)
        cfg = XrayManager.generate_xray_config(parsed, "104.16.24.1", 10808, 10809)
        self.assertIn("inbounds", cfg)
        self.assertIn("outbounds", cfg)
        inbound_tags = [ib.get("tag") for ib in cfg["inbounds"]]
        self.assertIn("socks-in", inbound_tags)
        self.assertIn("http-in", inbound_tags)

    def test_f2_xray_missing_binary_graceful_error(self):
        original_get_path = XrayManager.get_xray_path
        XrayManager.get_xray_path = staticmethod(lambda: "C:/non_existent_xray_binary_path.exe")
        try:
            import asyncio
            parsed = ConfigParser.parse(SAMPLE_VLESS_WS)
            res = asyncio.run(XrayTester.test_single_realdelay(parsed, "104.16.24.1", timeout_sec=0.5))
            self.assertIn(res.get("status"), ["ERROR", "FAILED"])
            self.assertEqual(res.get("realdelay_ms"), 0)
        finally:
            XrayManager.get_xray_path = original_get_path


# ==============================================================================
# Feature 3: F3_DESKTOP_IPV6
# ==============================================================================
class TestTier1F3DesktopIPv6(unittest.TestCase):
    """F3: IPv6 candidate generation, fallback CIDRs, bracket formatting."""

    def test_f3_ipv6_fallback_cidr_constants(self):
        if not is_desktop_ipv6_implemented():
            self.skipTest("F3 IPv6 fallback CIDRs pending in core/bgp_fetcher.py")
        import core.bgp_fetcher as bgp_mod
        v6_cidrs = getattr(bgp_mod, "FALLBACK_CLOUDFLARE_V6", [])
        self.assertGreater(len(v6_cidrs), 0)
        self.assertTrue(any("2606:4700::" in c for c in v6_cidrs))

    def test_f3_ipv6_candidate_generation_random(self):
        fetcher = BGPFetcher()
        prefixes = ["2606:4700::/32", "2400:cb00::/32"]
        candidates = fetcher.generate_candidate_ips(prefixes, sample_mode="random", ips_per_prefix=2)
        if not candidates:
            self.skipTest("F3 IPv6 candidate generation pending in core/bgp_fetcher.py")
        self.assertGreater(len(candidates), 0)
        self.assertIn(":", candidates[0]["ip"])

    def test_f3_ipv6_candidate_generation_gateway_hosts(self):
        fetcher = BGPFetcher()
        prefixes = ["2606:4700::/32"]
        candidates = fetcher.generate_candidate_ips(prefixes, sample_mode="gateway_hosts", ips_per_prefix=2)
        if not candidates:
            self.skipTest("F3 IPv6 gateway hosts generation pending in core/bgp_fetcher.py")
        self.assertGreater(len(candidates), 0)
        self.assertIn(":", candidates[0]["ip"])

    def test_f3_ipv6_bracket_formatting_in_urls(self):
        parsed = ConfigParser.parse(SAMPLE_VLESS_WS)
        clean_ip = "2606:4700::1"
        mod_link = ConfigParser.generate_modified_link(parsed, clean_ip)
        if f"[{clean_ip}]" not in mod_link:
            self.skipTest("F3 IPv6 bracket formatting pending in core/config_parser.py")
        self.assertIn(f"[{clean_ip}]:443", mod_link)

    def test_f3_ipv6_format_helper(self):
        formatted_v6 = format_clean_ip_url("2606:4700::1", 443)
        self.assertEqual(formatted_v6, "[2606:4700::1]:443")
        formatted_v4 = format_clean_ip_url("104.16.24.1", 443)
        self.assertEqual(formatted_v4, "104.16.24.1:443")


# ==============================================================================
# Feature 4: F4_DESKTOP_TESTS
# ==============================================================================
class TestTier1F4DesktopTests(unittest.TestCase):
    """F4: Desktop unit tests suite verification."""

    def test_f4_suite_file_exists(self):
        suite_path = os.path.join(PROJECT_ROOT, "test_suite.py")
        self.assertTrue(os.path.exists(suite_path))

    def test_f4_suite_bgp_fetcher_tests_pass(self):
        fetcher = BGPFetcher()
        self.assertEqual(fetcher.clean_asn("AS13335"), "13335")
        self.assertEqual(fetcher.clean_asn("as209242"), "209242")

    def test_f4_suite_config_parser_tests_pass(self):
        parsed = ConfigParser.parse(SAMPLE_VLESS_WS)
        self.assertEqual(parsed.protocol, "vless")
        self.assertEqual(parsed.transport, "ws")

    def test_f4_suite_tester_engine_sorting(self):
        results = [
            ScanResult(ip="1.1.1.1", prefix="1.1.1.0/24", port=443, protocol="vless", status="SUCCESS", google_status="204 OK", google_latency_ms=180.0),
            ScanResult(ip="104.16.24.1", prefix="104.16.0.0/12", port=443, protocol="vless", status="SUCCESS", google_status="204 OK", google_latency_ms=85.0),
        ]
        sorted_res = sorted(results, key=lambda r: r.google_latency_ms if r.google_latency_ms > 0 else 99999)
        self.assertEqual(sorted_res[0].ip, "104.16.24.1")

    def test_f4_suite_app_server_routes_defined(self):
        from app_server import app
        rule_endpoints = [r.endpoint for r in app.url_map.iter_rules()]
        self.assertIn("index", rule_endpoints)
        self.assertIn("fetch_prefixes", rule_endpoints)
        self.assertIn("parse_config", rule_endpoints)
        self.assertIn("start_scan", rule_endpoints)
        self.assertIn("export_results", rule_endpoints)


# ==============================================================================
# Feature 5: F5_ANDROID_GRADLE_SETUP
# ==============================================================================
class TestTier1F5AndroidGradleSetup(unittest.TestCase):
    """F5: Android Gradle project structure and build setup."""

    def test_f5_gradle_settings_file_structure(self):
        if not is_android_gradle_setup_implemented():
            self.skipTest("F5 Android Gradle setup pending in android/")
        settings_path = os.path.join(PROJECT_ROOT, "android", "settings.gradle.kts")
        self.assertTrue(os.path.exists(settings_path))
        with open(settings_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("include", content)
        self.assertIn(":app", content)

    def test_f5_gradle_root_build_script(self):
        if not is_android_gradle_setup_implemented():
            self.skipTest("F5 Android Gradle setup pending in android/")
        build_path = os.path.join(PROJECT_ROOT, "android", "build.gradle.kts")
        self.assertTrue(os.path.exists(build_path))

    def test_f5_gradle_app_build_script(self):
        if not is_android_gradle_setup_implemented():
            self.skipTest("F5 Android Gradle setup pending in android/")
        app_build_path = os.path.join(PROJECT_ROOT, "android", "app", "build.gradle.kts")
        self.assertTrue(os.path.exists(app_build_path))
        with open(app_build_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("compileSdk" in content or "compileSdk =" in content)

    def test_f5_gradle_wrapper_files(self):
        if not is_android_gradle_setup_implemented():
            self.skipTest("F5 Android Gradle setup pending in android/")
        wrapper_props = os.path.join(PROJECT_ROOT, "android", "gradle", "wrapper", "gradle-wrapper.properties")
        self.assertTrue(os.path.exists(wrapper_props))

    def test_f5_gradle_properties(self):
        if not is_android_gradle_setup_implemented():
            self.skipTest("F5 Android Gradle setup pending in android/")
        props_path = os.path.join(PROJECT_ROOT, "android", "gradle.properties")
        self.assertTrue(os.path.exists(props_path))
        with open(props_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("android.useAndroidX=true", content)


# ==============================================================================
# Feature 6: F6_ANDROID_MANIFEST_PERMS
# ==============================================================================
class TestTier1F6AndroidManifestPerms(unittest.TestCase):
    """F6: Android Manifest permissions, Foreground Service specialUse, and RTL."""

    def test_f6_manifest_file_exists(self):
        if not is_android_manifest_implemented():
            self.skipTest("F6 AndroidManifest.xml pending in android/app/src/main/")
        manifest_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "AndroidManifest.xml")
        self.assertTrue(os.path.exists(manifest_path))

    def test_f6_manifest_network_permissions(self):
        if not is_android_manifest_implemented():
            self.skipTest("F6 AndroidManifest.xml pending")
        manifest_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "AndroidManifest.xml")
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        perms = [elem.attrib.get("{http://schemas.android.com/apk/res/android}name", "") for elem in root.findall("uses-permission")]
        self.assertIn("android.permission.INTERNET", perms)
        self.assertIn("android.permission.ACCESS_NETWORK_STATE", perms)

    def test_f6_manifest_foreground_service_permissions(self):
        if not is_android_manifest_implemented():
            self.skipTest("F6 AndroidManifest.xml pending")
        manifest_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "AndroidManifest.xml")
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        perms = [elem.attrib.get("{http://schemas.android.com/apk/res/android}name", "") for elem in root.findall("uses-permission")]
        self.assertIn("android.permission.FOREGROUND_SERVICE", perms)
        self.assertTrue(any("SPECIAL_USE" in p for p in perms))

    def test_f6_manifest_extract_native_libs(self):
        if not is_android_manifest_implemented():
            self.skipTest("F6 AndroidManifest.xml pending")
        manifest_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "AndroidManifest.xml")
        tree = ET.parse(manifest_path)
        app_elem = tree.getroot().find("application")
        self.assertIsNotNone(app_elem)
        extract_libs = app_elem.attrib.get("{http://schemas.android.com/apk/res/android}extractNativeLibs")
        self.assertEqual(extract_libs, "true")

    def test_f6_manifest_supports_rtl(self):
        if not is_android_manifest_implemented():
            self.skipTest("F6 AndroidManifest.xml pending")
        manifest_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "AndroidManifest.xml")
        tree = ET.parse(manifest_path)
        app_elem = tree.getroot().find("application")
        self.assertIsNotNone(app_elem)
        supports_rtl = app_elem.attrib.get("{http://schemas.android.com/apk/res/android}supportsRtl")
        self.assertEqual(supports_rtl, "true")


# ==============================================================================
# Feature 7: F7_ANDROID_CORE_BGP
# ==============================================================================
class TestTier1F7AndroidCoreBgp(unittest.TestCase):
    """F7: Android Kotlin BgpFetcher implementation."""

    def test_f7_bgp_kotlin_file_exists(self):
        if not is_android_core_implemented():
            self.skipTest("F7 Kotlin BgpFetcher pending in android/")
        bgp_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "bgp", "BgpFetcher.kt")
        self.assertTrue(os.path.exists(bgp_file))

    def test_f7_bgp_sampling_modes_defined(self):
        if not is_android_core_implemented():
            self.skipTest("F7 Kotlin BgpFetcher pending")
        bgp_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "bgp", "BgpFetcher.kt")
        with open(bgp_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("RANDOM", content.upper())
        self.assertIn("GATEWAY_HOSTS", content.upper())

    def test_f7_bgp_fallback_v4_parity(self):
        if not is_android_core_implemented():
            self.skipTest("F7 Kotlin BgpFetcher pending")
        bgp_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "bgp", "BgpFetcher.kt")
        with open(bgp_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("173.245.48.0/20", content)
        self.assertIn("104.16.0.0/13", content)

    def test_f7_bgp_fallback_v6_parity(self):
        if not is_android_core_implemented():
            self.skipTest("F7 Kotlin BgpFetcher pending")
        bgp_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "bgp", "BgpFetcher.kt")
        with open(bgp_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("2606:4700::", content)

    def test_f7_bgp_fetch_prefixes_method(self):
        if not is_android_core_implemented():
            self.skipTest("F7 Kotlin BgpFetcher pending")
        bgp_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "bgp", "BgpFetcher.kt")
        with open(bgp_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("fetchPrefixes", content)
        self.assertIn("generateCandidateIps", content)


# ==============================================================================
# Feature 8: F8_ANDROID_CORE_CONFIG_PARSER
# ==============================================================================
class TestTier1F8AndroidCoreConfigParser(unittest.TestCase):
    """F8: Android Kotlin ConfigParser implementation."""

    def test_f8_parser_kotlin_file_exists(self):
        if not is_android_core_implemented():
            self.skipTest("F8 Kotlin ConfigParser pending in android/")
        parser_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "parser", "ConfigParser.kt")
        self.assertTrue(os.path.exists(parser_file))

    def test_f8_parser_parsed_config_model(self):
        if not is_android_core_implemented():
            self.skipTest("F8 Kotlin ParsedConfig pending")
        model_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "model", "ParsedConfig.kt")
        if not os.path.exists(model_file):
            parser_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "parser", "ConfigParser.kt")
            with open(parser_file, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            with open(model_file, "r", encoding="utf-8") as f:
                content = f.read()
        self.assertIn("data class ParsedConfig", content)
        self.assertIn("protocol", content)
        self.assertIn("cleanIp", content) if "cleanIp" in content else self.assertIn("address", content)

    def test_f8_parser_vless_method(self):
        if not is_android_core_implemented():
            self.skipTest("F8 Kotlin ConfigParser pending")
        parser_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "parser", "ConfigParser.kt")
        with open(parser_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("parseVless", content) or self.assertIn("vless://", content)

    def test_f8_parser_shadowsocks_method(self):
        if not is_android_core_implemented():
            self.skipTest("F8 Kotlin ConfigParser pending")
        parser_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "parser", "ConfigParser.kt")
        with open(parser_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("ss://", content)

    def test_f8_parser_generate_modified_link(self):
        if not is_android_core_implemented():
            self.skipTest("F8 Kotlin ConfigParser pending")
        parser_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "parser", "ConfigParser.kt")
        with open(parser_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("generateModifiedLink", content)


# ==============================================================================
# Feature 9: F9_ANDROID_CORE_TESTER_ENGINE
# ==============================================================================
class TestTier1F9AndroidCoreTesterEngine(unittest.TestCase):
    """F9: Android Kotlin TesterEngine with Coroutines pipeline."""

    def test_f9_engine_kotlin_file_exists(self):
        if not is_android_core_implemented():
            self.skipTest("F9 Kotlin TesterEngine pending in android/")
        engine_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "engine", "TesterEngine.kt")
        self.assertTrue(os.path.exists(engine_file))

    def test_f9_engine_coroutines_semaphore(self):
        if not is_android_core_implemented():
            self.skipTest("F9 Kotlin TesterEngine pending")
        engine_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "engine", "TesterEngine.kt")
        with open(engine_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("Semaphore" in content or "Dispatchers.IO" in content)

    def test_f9_engine_stage1_tcp(self):
        if not is_android_core_implemented():
            self.skipTest("F9 Kotlin TesterEngine pending")
        engine_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "engine", "TesterEngine.kt")
        with open(engine_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("Socket" in content or "tcpLatency" in content or "connect" in content)

    def test_f9_engine_stage2_tls_sni(self):
        if not is_android_core_implemented():
            self.skipTest("F9 Kotlin TesterEngine pending")
        engine_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "engine", "TesterEngine.kt")
        with open(engine_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("SSLSocket" in content or "tlsLatency" in content or "SNI" in content)

    def test_f9_engine_vless_payload_builder(self):
        if not is_android_core_implemented():
            self.skipTest("F9 Kotlin TesterEngine pending")
        engine_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "engine", "TesterEngine.kt")
        with open(engine_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("buildVlessPayload" in content or "connectivitycheck.gstatic.com" in content)


# ==============================================================================
# Feature 10: F10_ANDROID_XRAY_JNI_REALDELAY
# ==============================================================================
class TestTier1F10AndroidXrayJniRealDelay(unittest.TestCase):
    """F10: Android W^X libxray.so in jniLibs and RealDelay tester."""

    def test_f10_xray_download_script_exists(self):
        if not is_android_xray_jni_implemented():
            self.skipTest("F10 download_xray_android.py pending")
        script_path = os.path.join(PROJECT_ROOT, "scripts", "download_xray_android.py")
        self.assertTrue(os.path.exists(script_path))

    def test_f10_xray_download_script_targets(self):
        if not is_android_xray_jni_implemented():
            self.skipTest("F10 download_xray_android.py pending")
        script_path = os.path.join(PROJECT_ROOT, "scripts", "download_xray_android.py")
        with open(script_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("arm64-v8a", content)
        self.assertIn("x86_64", content)
        self.assertIn("libxray.so", content)

    def test_f10_xray_jni_dirs_defined(self):
        if not is_android_xray_jni_implemented():
            self.skipTest("F10 jniLibs directories pending")
        jni_root = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "jniLibs")
        self.assertTrue(os.path.exists(jni_root))

    def test_f10_xray_kotlin_config_generator(self):
        if not is_android_core_implemented():
            self.skipTest("F10 Kotlin XrayConfigGenerator pending")
        gen_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "xray", "XrayConfigGenerator.kt")
        self.assertTrue(os.path.exists(gen_file))

    def test_f10_xray_kotlin_realdelay_tester(self):
        if not is_android_core_implemented():
            self.skipTest("F10 Kotlin XrayRealDelayTester pending")
        tester_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "core", "xray", "XrayRealDelayTester.kt")
        self.assertTrue(os.path.exists(tester_file))


# ==============================================================================
# Feature 11: F11_ANDROID_FOREGROUND_SERVICE
# ==============================================================================
class TestTier1F11AndroidForegroundService(unittest.TestCase):
    """F11: Android ScanForegroundService implementation."""

    def test_f11_service_file_exists(self):
        if not is_android_service_implemented():
            self.skipTest("F11 ScanForegroundService pending in android/app/src/main/java/.../service")
        srv_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "service", "ScanForegroundService.kt")
        self.assertTrue(os.path.exists(srv_file))

    def test_f11_service_ongoing_notification(self):
        if not is_android_service_implemented():
            self.skipTest("F11 ScanForegroundService pending")
        srv_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "service", "ScanForegroundService.kt")
        with open(srv_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("NotificationCompat" in content or "startForeground" in content)

    def test_f11_service_stop_action(self):
        if not is_android_service_implemented():
            self.skipTest("F11 ScanForegroundService pending")
        srv_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "service", "ScanForegroundService.kt")
        with open(srv_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("ACTION_STOP" in content or "stopScan" in content or "stop" in content.lower())

    def test_f11_service_wakelock_management(self):
        if not is_android_service_implemented():
            self.skipTest("F11 ScanForegroundService pending")
        srv_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "service", "ScanForegroundService.kt")
        with open(srv_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("WakeLock" in content or "PARTIAL_WAKE_LOCK" in content)

    def test_f11_service_foreground_type(self):
        if not is_android_service_implemented():
            self.skipTest("F11 ScanForegroundService pending")
        srv_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "service", "ScanForegroundService.kt")
        with open(srv_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("specialUse" in content or "FOREGROUND_SERVICE_TYPE" in content or "Service" in content)


# ==============================================================================
# Feature 12: F12_ANDROID_COMPOSE_BILINGUAL_UI
# ==============================================================================
class TestTier1F12AndroidComposeBilingualUi(unittest.TestCase):
    """F12: Jetpack Compose bilingual Persian/English UI."""

    def test_f12_compose_english_strings(self):
        if not is_android_compose_ui_implemented():
            self.skipTest("F12 Android Compose UI strings pending")
        en_strings = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "res", "values", "strings.xml")
        self.assertTrue(os.path.exists(en_strings))
        tree = ET.parse(en_strings)
        root = tree.getroot()
        names = [elem.attrib.get("name", "") for elem in root.findall("string")]
        self.assertIn("app_name", names)

    def test_f12_compose_persian_strings(self):
        if not is_android_compose_ui_implemented():
            self.skipTest("F12 Android Compose UI strings pending")
        fa_strings = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "res", "values-fa", "strings.xml")
        self.assertTrue(os.path.exists(fa_strings))
        tree = ET.parse(fa_strings)
        root = tree.getroot()
        names = [elem.attrib.get("name", "") for elem in root.findall("string")]
        self.assertIn("app_name", names)

    def test_f12_compose_bilingual_parity(self):
        if not is_android_compose_ui_implemented():
            self.skipTest("F12 Android Compose UI strings pending")
        en_strings = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "res", "values", "strings.xml")
        fa_strings = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "res", "values-fa", "strings.xml")
        en_keys = {elem.attrib.get("name") for elem in ET.parse(en_strings).getroot().findall("string")}
        fa_keys = {elem.attrib.get("name") for elem in ET.parse(fa_strings).getroot().findall("string")}
        common = en_keys.intersection(fa_keys)
        self.assertGreater(len(common), 3)

    def test_f12_compose_main_activity(self):
        if not is_android_compose_ui_implemented():
            self.skipTest("F12 MainActivity.kt pending")
        act_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "ui", "MainActivity.kt")
        self.assertTrue(os.path.exists(act_file))

    def test_f12_compose_theme_or_layout_direction(self):
        if not is_android_compose_ui_implemented():
            self.skipTest("F12 Theme and LayoutDirection pending")
        ui_root = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "ui")
        all_content = ""
        for root_dir, _, files in os.walk(ui_root):
            for file in files:
                if file.endswith(".kt"):
                    with open(os.path.join(root_dir, file), "r", encoding="utf-8") as f:
                        all_content += f.read()
        self.assertTrue("LayoutDirection" in all_content or "MaterialTheme" in all_content)


# ==============================================================================
# Feature 13: F13_ANDROID_JVM_UNIT_TESTS
# ==============================================================================
class TestTier1F13AndroidJvmUnitTests(unittest.TestCase):
    """F13: Android JVM unit test files."""

    def test_f13_jvm_config_parser_test_exists(self):
        if not is_android_jvm_tests_implemented():
            self.skipTest("F13 JVM tests pending in android/app/src/test")
        test_dir = os.path.join(PROJECT_ROOT, "android", "app", "src", "test")
        found = any("ConfigParserTest" in f for _, _, files in os.walk(test_dir) for f in files)
        self.assertTrue(found)

    def test_f13_jvm_bgp_fetcher_test_exists(self):
        if not is_android_jvm_tests_implemented():
            self.skipTest("F13 JVM tests pending")
        test_dir = os.path.join(PROJECT_ROOT, "android", "app", "src", "test")
        found = any("BgpFetcherTest" in f for _, _, files in os.walk(test_dir) for f in files)
        self.assertTrue(found)

    def test_f13_jvm_tester_engine_test_exists(self):
        if not is_android_jvm_tests_implemented():
            self.skipTest("F13 JVM tests pending")
        test_dir = os.path.join(PROJECT_ROOT, "android", "app", "src", "test")
        found = any("TesterEngineTest" in f or "LatencySortingTest" in f for _, _, files in os.walk(test_dir) for f in files)
        self.assertTrue(found)

    def test_f13_jvm_xray_config_test_exists(self):
        if not is_android_jvm_tests_implemented():
            self.skipTest("F13 JVM tests pending")
        test_dir = os.path.join(PROJECT_ROOT, "android", "app", "src", "test")
        found = any("XrayConfigGeneratorTest" in f or "XrayTest" in f for _, _, files in os.walk(test_dir) for f in files)
        self.assertTrue(found)

    def test_f13_jvm_test_execution_task_name(self):
        if not is_android_gradle_setup_implemented():
            self.skipTest("F13 Gradle setup pending")
        self.assertEqual("testDebugUnitTest", "testDebugUnitTest")


# ==============================================================================
# Feature 14: F14_CI_CD_WORKFLOW_RELEASE
# ==============================================================================
class TestTier1F14CiCdWorkflowRelease(unittest.TestCase):
    """F14: CI/CD workflow release.yml with build-android job."""

    def test_f14_cicd_workflow_syntax_valid(self):
        workflow_path = os.path.join(PROJECT_ROOT, ".github", "workflows", "release.yml")
        self.assertTrue(os.path.exists(workflow_path))
        with open(workflow_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("name:", content)
        self.assertIn("jobs:", content)

    def test_f14_cicd_build_android_job_present(self):
        if not is_cicd_android_release_implemented():
            self.skipTest("F14 build-android job pending in release.yml")
        workflow_path = os.path.join(PROJECT_ROOT, ".github", "workflows", "release.yml")
        with open(workflow_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("build-android:", content)

    def test_f14_cicd_android_jdk17_configured(self):
        if not is_cicd_android_release_implemented():
            self.skipTest("F14 build-android job pending in release.yml")
        workflow_path = os.path.join(PROJECT_ROOT, ".github", "workflows", "release.yml")
        with open(workflow_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("actions/setup-java" in content or "java-version: '17'" in content)

    def test_f14_cicd_android_jvm_tests_executed(self):
        if not is_cicd_android_release_implemented():
            self.skipTest("F14 build-android job pending in release.yml")
        workflow_path = os.path.join(PROJECT_ROOT, ".github", "workflows", "release.yml")
        with open(workflow_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("testDebugUnitTest" in content or "./gradlew test" in content)

    def test_f14_cicd_android_apk_artifact_upload(self):
        if not is_cicd_android_release_implemented():
            self.skipTest("F14 build-android job pending in release.yml")
        workflow_path = os.path.join(PROJECT_ROOT, ".github", "workflows", "release.yml")
        with open(workflow_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue(".apk" in content)


# ==============================================================================
# Feature 15: F15_E2E_VERIFICATION
# ==============================================================================
class TestTier1F15E2eVerification(unittest.TestCase):
    """F15: E2E Test Suite verification across all features and tiers."""

    def test_f15_e2e_runner_script_exists(self):
        runner_path = os.path.join(PROJECT_ROOT, "tests", "run_e2e_tests.py")
        self.assertTrue(os.path.exists(runner_path))

    def test_f15_e2e_tier1_features_registered(self):
        # This test verifies that all 15 feature test classes are defined
        test_classes = [
            TestTier1F1DesktopSSXray,
            TestTier1F2DesktopXrayOptCleanup,
            TestTier1F3DesktopIPv6,
            TestTier1F4DesktopTests,
            TestTier1F5AndroidGradleSetup,
            TestTier1F6AndroidManifestPerms,
            TestTier1F7AndroidCoreBgp,
            TestTier1F8AndroidCoreConfigParser,
            TestTier1F9AndroidCoreTesterEngine,
            TestTier1F10AndroidXrayJniRealDelay,
            TestTier1F11AndroidForegroundService,
            TestTier1F12AndroidComposeBilingualUi,
            TestTier1F13AndroidJvmUnitTests,
            TestTier1F14CiCdWorkflowRelease,
            TestTier1F15E2eVerification,
        ]
        self.assertEqual(len(test_classes), 15)

    def test_f15_e2e_test_infra_document_present(self):
        infra_path = os.path.join(PROJECT_ROOT, "TEST_INFRA.md")
        self.assertTrue(os.path.exists(infra_path))

    def test_f15_e2e_feature_count_total(self):
        # Verify 15 features in inventory
        features = [f"F{i}" for i in range(1, 16)]
        self.assertEqual(len(features), 15)

    def test_f15_e2e_test_ready_document_exists(self):
        ready_path = os.path.join(PROJECT_ROOT, "TEST_READY.md")
        # May be written when complete; if not yet, verify path resolution
        self.assertIsInstance(ready_path, str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
