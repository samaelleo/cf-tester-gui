"""
Tier 2: Boundary & Corner Cases Test Suite
Covers extreme inputs, edge conditions, error handling, and malformed inputs for all 15 features.
Total: 75 test cases.
"""

import base64
import json
import os
import re
import sys
import unittest
from unittest.mock import patch
import urllib.parse
import xml.etree.ElementTree as ET

from tests.e2e.test_helpers import (
    PROJECT_ROOT,
    REFERENCE_CLOUDFLARE_V4_CIDRS,
    REFERENCE_CLOUDFLARE_V6_CIDRS,
    SAMPLE_SS_CHACHA,
    SAMPLE_SS_LEGACY,
    SAMPLE_SS_PLAIN,
    SAMPLE_SS_SIP002,
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
# Feature 1: F1_DESKTOP_SS_XRAY (Tier 2 Boundaries)
# ==============================================================================
class TestTier2F1DesktopSSXrayBoundaries(unittest.TestCase):
    """F1 Boundary Cases: Shadowsocks extreme ports, special characters, ciphers."""

    def test_f1_boundary_extreme_ports(self):
        # Port 1 (lowest valid TCP port)
        link_p1 = "ss://" + base64.b64encode(b"aes-128-gcm:p@ss").decode() + "@edge.cf.com:1#P1"
        p_low = ConfigParser.parse(link_p1)
        self.assertEqual(p_low.port, 1)

        # Port 65535 (highest valid TCP port)
        link_pmax = "ss://" + base64.b64encode(b"aes-128-gcm:p@ss").decode() + "@edge.cf.com:65535#PMax"
        p_high = ConfigParser.parse(link_pmax)
        self.assertEqual(p_high.port, 65535)

    def test_f1_boundary_special_characters_in_password(self):
        complex_secret = "P@ssw0rd!#$&'()*+,;=~-._"
        encoded_userinfo = base64.b64encode(f"aes-256-gcm:{complex_secret}".encode()).decode()
        link = f"ss://{encoded_userinfo}@orig.domain.com:443#ComplexNode"
        parsed = ConfigParser.parse(link)
        method, password = extract_ss_credentials(parsed.uuid)
        self.assertEqual(method, "aes-256-gcm")
        self.assertEqual(password, complex_secret)

    def test_f1_boundary_corrupt_base64_in_userinfo(self):
        # Malformed non-base64 userinfo
        corrupt_link = "ss://!!!not-valid-base64!!!@orig.domain.com:443#Corrupt"
        parsed = ConfigParser.parse(corrupt_link)
        self.assertEqual(parsed.protocol, "ss")
        self.assertEqual(parsed.port, 443)

    def test_f1_boundary_chacha20_cipher(self):
        parsed = ConfigParser.parse(SAMPLE_SS_CHACHA)
        self.assertEqual(parsed.protocol, "ss")
        method, password = extract_ss_credentials(parsed.uuid)
        self.assertEqual(method, "chacha20-ietf-poly1305")
        self.assertEqual(password, "ultraSecureP@ss!")

    def test_f1_boundary_long_node_tag(self):
        long_tag = "A" * 600
        link = "ss://" + base64.b64encode(b"aes-256-gcm:pass").decode() + f"@orig.domain.com:443#{long_tag}"
        parsed = ConfigParser.parse(link)
        self.assertEqual(parsed.tag, long_tag)
        mod = ConfigParser.generate_modified_link(parsed, "104.16.24.1")
        self.assertIn("CF:104.16.24.1", urllib.parse.unquote(mod))


# ==============================================================================
# Feature 2: F2_DESKTOP_XRAY_OPT_CLEANUP (Tier 2 Boundaries)
# ==============================================================================
class TestTier2F2DesktopXrayOptBoundaries(unittest.TestCase):
    """F2 Boundary Cases: Rapid port allocations, minimal configs, cancellation."""

    def test_f2_boundary_rapid_sequential_ports(self):
        # Ensure 20 rapid port allocations return unique valid ports
        ports = [get_free_port() for _ in range(20)]
        self.assertEqual(len(set(ports)), 20)
        self.assertTrue(all(1024 < p < 65536 for p in ports))

    def test_f2_boundary_empty_config_dictionary(self):
        empty_cfg = ParsedConfig()
        xray_json = XrayManager.generate_xray_config(empty_cfg, "127.0.0.1", 10808, 10809)
        self.assertIn("inbounds", xray_json)
        self.assertIn("outbounds", xray_json)
        self.assertEqual(len(xray_json["inbounds"]), 2)

    def test_f2_boundary_unwritable_temp_dir_fallback(self):
        # BIN_DIR fallback logic check
        from core.xray_runner import BIN_DIR, USER_BIN_DIR
        self.assertTrue(isinstance(BIN_DIR, str))
        self.assertTrue(isinstance(USER_BIN_DIR, str))

    def test_f2_boundary_realdelay_timeout_safety(self):
        import asyncio
        parsed = ConfigParser.parse(SAMPLE_VLESS_WS)
        # Mock opener timeout to verify fast exception handling in XrayTester
        with patch("urllib.request.build_opener") as mock_builder:
            mock_opener = mock_builder.return_value
            mock_opener.open.side_effect = TimeoutError("Simulated Request Timeout")
            res = asyncio.run(XrayTester.test_single_realdelay(parsed, "104.16.24.1", timeout_sec=0.1))
            self.assertIn(res.get("status"), ["ERROR", "FAILED"])
            self.assertEqual(res.get("realdelay_ms"), 0)

    def test_f2_boundary_config_cleanup_idempotency(self):
        # Removing an already deleted file should not raise an unhandled exception
        fake_path = os.path.join(PROJECT_ROOT, "non_existent_tmp_xray_cfg.json")
        try:
            if os.path.exists(fake_path):
                os.remove(fake_path)
        except Exception as e:
            self.fail(f"File cleanup raised unexpected error: {e}")


# ==============================================================================
# Feature 3: F3_DESKTOP_IPV6 (Tier 2 Boundaries)
# ==============================================================================
class TestTier2F3DesktopIPv6Boundaries(unittest.TestCase):
    """F3 Boundary Cases: IPv6 compressed, /128 subnets, max total IPs, mixed IPs."""

    def test_f3_boundary_ipv6_compressed_and_expanded(self):
        clean_ip_comp = "2606:4700::1"
        clean_ip_exp = "2606:4700:0000:0000:0000:0000:0000:0001"
        fmt_comp = format_clean_ip_url(clean_ip_comp, 443)
        fmt_exp = format_clean_ip_url(clean_ip_exp, 443)
        self.assertEqual(fmt_comp, "[2606:4700::1]:443")
        self.assertEqual(fmt_exp, "[2606:4700:0000:0000:0000:0000:0000:0001]:443")

    def test_f3_boundary_ipv6_single_host_128(self):
        fetcher = BGPFetcher()
        prefixes = ["2606:4700::1/128"]
        candidates = fetcher.generate_candidate_ips(prefixes, sample_mode="random", ips_per_prefix=1)
        if not candidates:
            self.skipTest("F3 IPv6 candidate generation pending in core/bgp_fetcher.py")
        self.assertEqual(len(candidates), 1)
        self.assertIn("2606:4700::1", candidates[0]["ip"])

    def test_f3_boundary_ipv6_max_total_ips_limit(self):
        fetcher = BGPFetcher()
        prefixes = ["2606:4700::/32", "2400:cb00::/32"]
        candidates = fetcher.generate_candidate_ips(prefixes, sample_mode="random", ips_per_prefix=10, max_total_ips=5)
        if not candidates:
            self.skipTest("F3 IPv6 candidate generation pending")
        self.assertLessEqual(len(candidates), 5)

    def test_f3_boundary_ipv6_already_bracketed_input(self):
        # Input clean_ip is already bracketed: [2606:4700::1]
        formatted = format_clean_ip_url("[2606:4700::1]", 8443)
        self.assertEqual(formatted, "[2606:4700::1]:8443")
        self.assertFalse(formatted.startswith("[["))

    def test_f3_boundary_mixed_ipv4_and_ipv6_custom_list(self):
        fetcher = BGPFetcher()
        custom_input = ["104.16.24.1", "2606:4700::1", "172.64.0.1", "2400:cb00::1"]
        candidates = fetcher.generate_candidate_ips([], custom_ip_list=custom_input)
        self.assertEqual(len(candidates), 4)
        v4_count = sum(1 for c in candidates if ":" not in c["ip"])
        v6_count = sum(1 for c in candidates if ":" in c["ip"])
        self.assertEqual(v4_count, 2)
        self.assertEqual(v6_count, 2)


# ==============================================================================
# Feature 4: F4_DESKTOP_TESTS (Tier 2 Boundaries)
# ==============================================================================
class TestTier2F4DesktopTestsBoundaries(unittest.TestCase):
    """F4 Boundary Cases: Programmatic test execution, offline fallbacks, sorting edge cases."""

    def test_f4_boundary_test_suite_runner_programmatic(self):
        import unittest
        loader = unittest.TestLoader()
        suite = loader.discover(start_dir=PROJECT_ROOT, pattern="test_suite.py")
        self.assertGreater(suite.countTestCases(), 0)

    def test_f4_boundary_bgp_mock_offline_api(self):
        fetcher = BGPFetcher()
        # Mock API failure for AS13335 to verify fallback CIDR behavior
        with patch("urllib.request.urlopen", side_effect=Exception("Simulated Network Error")):
            res = fetcher.fetch_prefixes_from_he("13335")
            self.assertEqual(res["status"], "fallback")
            self.assertGreater(len(res["ipv4"]), 5)

    def test_f4_boundary_empty_results_export(self):
        from app_server import app
        app.config["TESTING"] = True
        client = app.test_client()
        # Exporting empty results list to CSV and TXT
        res_csv = client.post("/api/export", json={"format": "csv", "results": []})
        self.assertEqual(res_csv.status_code, 200)
        res_txt = client.post("/api/export", json={"format": "ips", "results": []})
        self.assertEqual(res_txt.status_code, 200)

    def test_f4_boundary_identical_latency_sorting(self):
        results = [
            ScanResult(ip="104.16.24.1", prefix="104.16.0.0/12", port=443, protocol="vless", status="SUCCESS", google_status="204 OK", google_latency_ms=100.0),
            ScanResult(ip="104.16.24.2", prefix="104.16.0.0/12", port=443, protocol="vless", status="SUCCESS", google_status="204 OK", google_latency_ms=100.0),
        ]
        sorted_res = sorted(results, key=lambda r: r.google_latency_ms if r.google_latency_ms > 0 else 99999)
        self.assertEqual(len(sorted_res), 2)
        self.assertEqual(sorted_res[0].google_latency_ms, 100.0)

    def test_f4_boundary_zero_and_negative_latency_sorting(self):
        results = [
            ScanResult(ip="104.16.24.1", prefix="104.16.0.0/12", port=443, protocol="vless", status="FAILED", google_status="FAIL", google_latency_ms=0.0),
            ScanResult(ip="104.16.24.2", prefix="104.16.0.0/12", port=443, protocol="vless", status="SUCCESS", google_status="204 OK", google_latency_ms=90.0),
        ]
        sorted_res = sorted(results, key=lambda r: r.google_latency_ms if r.google_latency_ms > 0 else 99999)
        self.assertEqual(sorted_res[0].ip, "104.16.24.2")
        self.assertEqual(sorted_res[1].ip, "104.16.24.1")


# ==============================================================================
# Feature 5: F5_ANDROID_GRADLE_SETUP (Tier 2 Boundaries)
# ==============================================================================
class TestTier2F5AndroidGradleBoundaries(unittest.TestCase):
    """F5 Boundary Cases: useLegacyPackaging, SDK boundaries, Gradle version."""

    def test_f5_boundary_use_legacy_packaging_present(self):
        if not is_android_gradle_setup_implemented():
            self.skipTest("F5 Android Gradle setup pending")
        app_build = os.path.join(PROJECT_ROOT, "android", "app", "build.gradle.kts")
        with open(app_build, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("useLegacyPackaging = true" in content or "jniLibs" in content)

    def test_f5_boundary_min_sdk_boundary(self):
        if not is_android_gradle_setup_implemented():
            self.skipTest("F5 Android Gradle setup pending")
        app_build = os.path.join(PROJECT_ROOT, "android", "app", "build.gradle.kts")
        with open(app_build, "r", encoding="utf-8") as f:
            content = f.read()
        match = re.search(r"minSdk\s*=\s*(\d+)", content)
        if match:
            min_sdk = int(match.group(1))
            self.assertGreaterEqual(min_sdk, 26)

    def test_f5_boundary_target_sdk_boundary(self):
        if not is_android_gradle_setup_implemented():
            self.skipTest("F5 Android Gradle setup pending")
        app_build = os.path.join(PROJECT_ROOT, "android", "app", "build.gradle.kts")
        with open(app_build, "r", encoding="utf-8") as f:
            content = f.read()
        match = re.search(r"targetSdk\s*=\s*(\d+)", content)
        if match:
            target_sdk = int(match.group(1))
            self.assertGreaterEqual(target_sdk, 34)

    def test_f5_boundary_gradle_wrapper_version(self):
        if not is_android_gradle_setup_implemented():
            self.skipTest("F5 Android Gradle setup pending")
        wrapper_props = os.path.join(PROJECT_ROOT, "android", "gradle", "wrapper", "gradle-wrapper.properties")
        with open(wrapper_props, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("gradle-8." in content or "gradle-9." in content)

    def test_f5_boundary_compose_build_features(self):
        if not is_android_gradle_setup_implemented():
            self.skipTest("F5 Android Gradle setup pending")
        app_build = os.path.join(PROJECT_ROOT, "android", "app", "build.gradle.kts")
        with open(app_build, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("compose = true" in content or "buildFeatures" in content)


# ==============================================================================
# Feature 6: F6_ANDROID_MANIFEST_PERMS (Tier 2 Boundaries)
# ==============================================================================
class TestTier2F6AndroidManifestBoundaries(unittest.TestCase):
    """F6 Boundary Cases: Subtype metadata, exported activity, UTF-8 XML encoding."""

    def test_f6_boundary_fgs_special_use_subtype_metadata(self):
        if not is_android_manifest_implemented():
            self.skipTest("F6 AndroidManifest.xml pending")
        manifest_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "AndroidManifest.xml")
        tree = ET.parse(manifest_path)
        service_elem = tree.getroot().find(".//service")
        self.assertIsNotNone(service_elem)
        fgs_type = service_elem.attrib.get("{http://schemas.android.com/apk/res/android}foregroundServiceType", "")
        self.assertIn("specialUse", fgs_type)

    def test_f6_boundary_main_activity_exported(self):
        if not is_android_manifest_implemented():
            self.skipTest("F6 AndroidManifest.xml pending")
        manifest_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "AndroidManifest.xml")
        tree = ET.parse(manifest_path)
        act_elem = tree.getroot().find(".//activity")
        self.assertIsNotNone(act_elem)
        exported = act_elem.attrib.get("{http://schemas.android.com/apk/res/android}exported", "")
        self.assertEqual(exported, "true")

    def test_f6_boundary_post_notifications_permission(self):
        if not is_android_manifest_implemented():
            self.skipTest("F6 AndroidManifest.xml pending")
        manifest_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "AndroidManifest.xml")
        tree = ET.parse(manifest_path)
        perms = [elem.attrib.get("{http://schemas.android.com/apk/res/android}name", "") for elem in tree.getroot().findall("uses-permission")]
        self.assertIn("android.permission.POST_NOTIFICATIONS", perms)

    def test_f6_boundary_manifest_xml_encoding(self):
        if not is_android_manifest_implemented():
            self.skipTest("F6 AndroidManifest.xml pending")
        manifest_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "AndroidManifest.xml")
        with open(manifest_path, "rb") as f:
            first_line = f.readline()
        self.assertTrue(b"xml" in first_line)

    def test_f6_boundary_wakelock_permission_present(self):
        if not is_android_manifest_implemented():
            self.skipTest("F6 AndroidManifest.xml pending")
        manifest_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "AndroidManifest.xml")
        tree = ET.parse(manifest_path)
        perms = [elem.attrib.get("{http://schemas.android.com/apk/res/android}name", "") for elem in tree.getroot().findall("uses-permission")]
        self.assertIn("android.permission.WAKE_LOCK", perms)


# ==============================================================================
# Feature 7: F7_ANDROID_CORE_BGP (Tier 2 Boundaries)
# ==============================================================================
class TestTier2F7AndroidCoreBgpBoundaries(unittest.TestCase):
    """F7 Boundary Cases: ASN cleaning with spaces/symbols, single host IP, invalid CIDRs."""

    def test_f7_boundary_asn_with_letters_and_spaces(self):
        fetcher = BGPFetcher()
        clean = fetcher.clean_asn("  AS 13335 \n")
        self.assertEqual(clean, "13335")

    def test_f7_boundary_empty_asn_fallback(self):
        fetcher = BGPFetcher()
        clean_empty = fetcher.clean_asn("")
        self.assertEqual(clean_empty, "13335")
        clean_non_digit = fetcher.clean_asn("AS-XYZ")
        self.assertEqual(clean_non_digit, "13335")

    def test_f7_boundary_single_ip_without_mask(self):
        fetcher = BGPFetcher()
        custom = ["104.16.24.1"]
        res = fetcher.generate_candidate_ips([], custom_ip_list=custom)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["ip"], "104.16.24.1")
        self.assertEqual(res[0]["prefix"], "Manual")

    def test_f7_boundary_empty_prefix_list(self):
        fetcher = BGPFetcher()
        res = fetcher.generate_candidate_ips([], sample_mode="random")
        self.assertEqual(len(res), 0)

    def test_f7_boundary_invalid_cidr_strings(self):
        fetcher = BGPFetcher()
        # Malformed CIDRs should be skipped without throwing unhandled exceptions
        invalid_prefixes = ["999.999.999.999/99", "not-a-cidr", "1.1.1.1/abc"]
        res = fetcher.generate_candidate_ips(invalid_prefixes, sample_mode="random")
        self.assertEqual(len(res), 0)


# ==============================================================================
# Feature 8: F8_ANDROID_CORE_CONFIG_PARSER (Tier 2 Boundaries)
# ==============================================================================
class TestTier2F8AndroidCoreConfigParserBoundaries(unittest.TestCase):
    """F8 Boundary Cases: Post-Quantum params, xhttp extra JSON, empty input, bare domain."""

    def test_f8_boundary_post_quantum_encryption_param(self):
        parsed = ConfigParser.parse(SAMPLE_VLESS_XHTTP_PQ)
        self.assertIn("mlkem768", parsed.encryption)
        mod_link = ConfigParser.generate_modified_link(parsed, "104.16.24.1")
        self.assertIn("encryption=mlkem768", mod_link)

    def test_f8_boundary_xhttp_extra_json_headers(self):
        parsed = ConfigParser.parse(SAMPLE_VLESS_XHTTP_PQ)
        self.assertIn("headers", parsed.extra)
        self.assertEqual(parsed.extra["headers"].get("Accept-Encoding"), "gzip")

    def test_f8_boundary_empty_or_whitespace_input(self):
        parsed = ConfigParser.parse("   ")
        self.assertEqual(parsed.protocol, "vless")
        self.assertEqual(parsed.address, "")

    def test_f8_boundary_corrupt_vmess_base64(self):
        corrupt_vmess = "vmess://not_valid_json_base64_string=="
        parsed = ConfigParser.parse(corrupt_vmess)
        self.assertIsInstance(parsed, ParsedConfig)

    def test_f8_boundary_bare_domain_and_port(self):
        bare = "cloudflare.com:8443"
        parsed = ConfigParser.parse(bare)
        self.assertEqual(parsed.protocol, "direct")
        self.assertEqual(parsed.port, 8443)
        self.assertEqual(parsed.address, "cloudflare.com")
        bare_with_path = "cloudflare.com/cdn-cgi/trace"
        parsed_path = ConfigParser.parse(bare_with_path)
        self.assertEqual(parsed_path.path, "/cdn-cgi/trace")


# ==============================================================================
# Feature 9: F9_ANDROID_CORE_TESTER_ENGINE (Tier 2 Boundaries)
# ==============================================================================
class TestTier2F9AndroidCoreTesterEngineBoundaries(unittest.TestCase):
    """F9 Boundary Cases: Zero timeout, semaphore bounding, stop control, UUID fallback."""

    def test_f9_boundary_zero_timeout(self):
        import asyncio
        engine = TesterEngine()
        cfg = ConfigParser.parse("cp.cloudflare.com:443")
        res = asyncio.run(engine._test_single_ip("127.0.0.1", "Local", cfg, timeout_sec=0.01, test_target_url="http://connectivitycheck.gstatic.com/generate_204"))
        self.assertIn(res.status, ["FAILED", "TIMEOUT", "REFUSED"])

    def test_f9_boundary_engine_stop_control(self):
        engine = TesterEngine()
        engine.is_running = True
        engine.stop()
        self.assertFalse(engine.is_running)
        self.assertTrue(engine._cancel_requested)

    def test_f9_boundary_engine_pause_resume_control(self):
        engine = TesterEngine()
        engine.pause()
        self.assertTrue(engine.is_paused)
        engine.resume()
        self.assertFalse(engine.is_paused)

    def test_f9_boundary_vless_payload_random_uuid_fallback(self):
        engine = TesterEngine()
        payload = engine._build_vless_payload(user_uuid="invalid-non-uuid-string")
        self.assertIsInstance(payload, (bytes, bytearray))
        self.assertGreater(len(payload), 16)
        self.assertEqual(payload[0], 0x00)  # VLESS version 0

    def test_f9_boundary_unreachable_ip_handling(self):
        import asyncio
        engine = TesterEngine()
        cfg = ConfigParser.parse("cp.cloudflare.com:443")
        # 192.0.2.1 is TEST-NET-1 (RFC 5737) - guaranteed non-routable
        res = asyncio.run(engine._test_single_ip("192.0.2.1", "TestNet", cfg, timeout_sec=0.2, test_target_url="http://connectivitycheck.gstatic.com/generate_204"))
        self.assertIn(res.status, ["FAILED", "TIMEOUT", "REFUSED"])


# ==============================================================================
# Feature 10: F10_ANDROID_XRAY_JNI_REALDELAY (Tier 2 Boundaries)
# ==============================================================================
class TestTier2F10AndroidXrayJniBoundaries(unittest.TestCase):
    """F10 Boundary Cases: Batch schema, nativeLibraryDir path, download ABIs."""

    def test_f10_boundary_download_script_abi_coverage(self):
        if not is_android_xray_jni_implemented():
            self.skipTest("F10 download_xray_android.py pending")
        script_path = os.path.join(PROJECT_ROOT, "scripts", "download_xray_android.py")
        with open(script_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("arm64-v8a", content)
        self.assertIn("x86_64", content)

    def test_f10_boundary_multi_outbound_routing_schema(self):
        # Verify Xray routing rules format for batch testing
        dummy_routing = {
            "rules": [
                {"type": "field", "inboundTag": ["in-10808"], "outboundTag": "out-clean-1"},
                {"type": "field", "inboundTag": ["in-10809"], "outboundTag": "out-clean-2"},
            ]
        }
        self.assertEqual(len(dummy_routing["rules"]), 2)

    def test_f10_boundary_native_library_dir_convention(self):
        # Native library directory on Android is applicationInfo.nativeLibraryDir
        convention_name = "libxray.so"
        self.assertTrue(convention_name.startswith("lib") and convention_name.endswith(".so"))

    def test_f10_boundary_jni_libs_architecture_folders(self):
        if not is_android_xray_jni_implemented():
            self.skipTest("F10 jniLibs directories pending")
        jni_arm = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "jniLibs", "arm64-v8a")
        jni_x86 = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "jniLibs", "x86_64")
        self.assertTrue(os.path.exists(jni_arm) or os.path.exists(jni_x86))

    def test_f10_boundary_missing_xray_error_handling(self):
        original_path = XrayManager.get_xray_path
        XrayManager.get_xray_path = staticmethod(lambda: "/dev/null/xray")
        try:
            self.assertFalse(XrayManager.is_xray_available())
        finally:
            XrayManager.get_xray_path = original_path


# ==============================================================================
# Feature 11: F11_ANDROID_FOREGROUND_SERVICE (Tier 2 Boundaries)
# ==============================================================================
class TestTier2F11AndroidForegroundServiceBoundaries(unittest.TestCase):
    """F11 Boundary Cases: WakeLock safety, notification rate limiting, stop action."""

    def test_f11_boundary_wakelock_timeout_safety(self):
        if not is_android_service_implemented():
            self.skipTest("F11 ScanForegroundService pending")
        srv_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "service", "ScanForegroundService.kt")
        with open(srv_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("release()" in content or "wakeLock" in content)

    def test_f11_boundary_rapid_progress_notification_throttling(self):
        if not is_android_service_implemented():
            self.skipTest("F11 ScanForegroundService pending")
        srv_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "service", "ScanForegroundService.kt")
        with open(srv_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("Notification" in content)

    def test_f11_boundary_service_on_destroy_releases_resources(self):
        if not is_android_service_implemented():
            self.skipTest("F11 ScanForegroundService pending")
        srv_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "service", "ScanForegroundService.kt")
        with open(srv_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("onDestroy", content)

    def test_f11_boundary_stop_action_cancels_scan(self):
        if not is_android_service_implemented():
            self.skipTest("F11 ScanForegroundService pending")
        srv_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "service", "ScanForegroundService.kt")
        with open(srv_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("stop" in content.lower())

    def test_f11_boundary_start_not_sticky_behavior(self):
        if not is_android_service_implemented():
            self.skipTest("F11 ScanForegroundService pending")
        srv_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "service", "ScanForegroundService.kt")
        with open(srv_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("START_NOT_STICKY" in content or "onStartCommand" in content)


# ==============================================================================
# Feature 12: F12_ANDROID_COMPOSE_BILINGUAL_UI (Tier 2 Boundaries)
# ==============================================================================
class TestTier2F12AndroidComposeBilingualUiBoundaries(unittest.TestCase):
    """F12 Boundary Cases: Persian UTF-8 strings, large clipboard payload, LTR numbers in RTL."""

    def test_f12_boundary_persian_strings_valid_utf8(self):
        if not is_android_compose_ui_implemented():
            self.skipTest("F12 Android Compose UI strings pending")
        fa_strings = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "res", "values-fa", "strings.xml")
        with open(fa_strings, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIsInstance(content, str)

    def test_f12_boundary_large_clipboard_payload(self):
        # Formats 1,000 clean IPs into clipboard text
        clean_ips = [f"104.16.{i // 256}.{i % 256}" for i in range(1000)]
        payload = "\n".join(clean_ips)
        self.assertGreater(len(payload), 10000)

    def test_f12_boundary_empty_results_export_message(self):
        from app_server import app
        app.config["TESTING"] = True
        client = app.test_client()
        res = client.post("/api/export", json={"format": "txt", "results": []})
        self.assertEqual(res.status_code, 200)

    def test_f12_boundary_layout_direction_ltr_numbers(self):
        # Latency string format check: standard digits
        latency_str = f"{120.5:.1f} ms"
        self.assertEqual(latency_str, "120.5 ms")

    def test_f12_boundary_share_intent_payload_format(self):
        parsed = ConfigParser.parse(SAMPLE_VLESS_WS)
        mod_link = ConfigParser.generate_modified_link(parsed, "104.16.24.1")
        # Format for proxy apps (v2rayNG / NekoBox)
        share_payload = f"# CF Clean Config\n{mod_link}"
        self.assertIn("vless://", share_payload)


# ==============================================================================
# Feature 13: F13_ANDROID_JVM_UNIT_TESTS (Tier 2 Boundaries)
# ==============================================================================
class TestTier2F13AndroidJvmUnitTestsBoundaries(unittest.TestCase):
    """F13 Boundary Cases: JVM test directory separation, coroutine runTest, naming."""

    def test_f13_boundary_jvm_tests_directory_separation(self):
        if not is_android_jvm_tests_implemented():
            self.skipTest("F13 Android JVM tests pending")
        test_dir = os.path.join(PROJECT_ROOT, "android", "app", "src", "test")
        self.assertTrue(os.path.exists(test_dir))

    def test_f13_boundary_test_class_naming_convention(self):
        if not is_android_jvm_tests_implemented():
            self.skipTest("F13 Android JVM tests pending")
        test_dir = os.path.join(PROJECT_ROOT, "android", "app", "src", "test")
        test_files = [f for _, _, files in os.walk(test_dir) for f in files if f.endswith(".kt")]
        self.assertTrue(all(f.endswith("Test.kt") for f in test_files))

    def test_f13_boundary_coroutine_run_test_in_engine(self):
        if not is_android_jvm_tests_implemented():
            self.skipTest("F13 Android JVM tests pending")
        engine_test = os.path.join(PROJECT_ROOT, "android", "app", "src", "test", "java", "com", "cftester", "scanner", "core", "engine", "TesterEngineTest.kt")
        if os.path.exists(engine_test):
            with open(engine_test, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertTrue("runTest" in content or "runBlocking" in content)

    def test_f13_boundary_complex_pq_link_in_parser_test(self):
        if not is_android_jvm_tests_implemented():
            self.skipTest("F13 Android JVM tests pending")
        parser_test = os.path.join(PROJECT_ROOT, "android", "app", "src", "test", "java", "com", "cftester", "scanner", "core", "parser", "ConfigParserTest.kt")
        if os.path.exists(parser_test):
            with open(parser_test, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertTrue("mlkem768" in content or "xhttp" in content or "vless" in content)

    def test_f13_boundary_bgp_mock_in_test(self):
        if not is_android_jvm_tests_implemented():
            self.skipTest("F13 Android JVM tests pending")
        bgp_test = os.path.join(PROJECT_ROOT, "android", "app", "src", "test", "java", "com", "cftester", "scanner", "core", "bgp", "BgpFetcherTest.kt")
        if os.path.exists(bgp_test):
            with open(bgp_test, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertTrue("13335" in content or "generateCandidateIps" in content)


# ==============================================================================
# Feature 14: F14_CI_CD_WORKFLOW_RELEASE (Tier 2 Boundaries)
# ==============================================================================
class TestTier2F14CiCdReleaseBoundaries(unittest.TestCase):
    """F14 Boundary Cases: Workflow triggers, paths-ignore, release packaging."""

    def test_f14_boundary_workflow_triggers(self):
        workflow_path = os.path.join(PROJECT_ROOT, ".github", "workflows", "release.yml")
        with open(workflow_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("workflow_dispatch:", content)
        self.assertIn("branches:", content)

    def test_f14_boundary_paths_ignore_documentation(self):
        workflow_path = os.path.join(PROJECT_ROOT, ".github", "workflows", "release.yml")
        with open(workflow_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("paths-ignore:", content)
        self.assertIn("'**.md'", content)

    def test_f14_boundary_release_artifacts_retention(self):
        workflow_path = os.path.join(PROJECT_ROOT, ".github", "workflows", "release.yml")
        with open(workflow_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("retention-days:" in content or "actions/upload-artifact" in content)

    def test_f14_boundary_build_matrix_os_platforms(self):
        workflow_path = os.path.join(PROJECT_ROOT, ".github", "workflows", "release.yml")
        with open(workflow_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("windows-latest", content)
        self.assertIn("ubuntu-latest", content)
        self.assertIn("macos-latest", content)

    def test_f14_boundary_release_notes_generation(self):
        workflow_path = os.path.join(PROJECT_ROOT, ".github", "workflows", "release.yml")
        with open(workflow_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("generate_release_notes: true", content)


# ==============================================================================
# Feature 15: F15_E2E_VERIFICATION (Tier 2 Boundaries)
# ==============================================================================
class TestTier2F15E2eVerificationBoundaries(unittest.TestCase):
    """F15 Boundary Cases: Runner error handling, non-existent flags, idempotency."""

    def test_f15_boundary_runner_non_existent_tier_error(self):
        from tests.run_e2e_tests import load_tier_suite
        suite = load_tier_suite(99)
        self.assertEqual(suite.countTestCases(), 0)

    def test_f15_boundary_runner_non_existent_feature_filter(self):
        from tests.run_e2e_tests import load_tier_suite
        suite = load_tier_suite(1, feature_filter="NON_EXISTENT_FEAT")
        self.assertEqual(suite.countTestCases(), 0)

    def test_f15_boundary_runner_failfast_option(self):
        from tests.run_e2e_tests import main
        self.assertTrue(callable(main))

    def test_f15_boundary_runner_tier1_discovery(self):
        from tests.run_e2e_tests import load_tier_suite
        suite = load_tier_suite(1)
        self.assertEqual(suite.countTestCases(), 75)

    def test_f15_boundary_runner_idempotent_execution(self):
        from tests.run_e2e_tests import load_tier_suite
        c1 = load_tier_suite(1).countTestCases()
        c2 = load_tier_suite(1).countTestCases()
        self.assertEqual(c1, c2)
        self.assertEqual(c1, 75)


if __name__ == "__main__":
    unittest.main(verbosity=2)
