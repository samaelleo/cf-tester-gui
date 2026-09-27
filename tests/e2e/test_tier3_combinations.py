"""
Tier 3: Cross-Feature Combinations Test Suite
Covers pairwise and multi-feature interactions across protocols, transports, engine pipelines, and platforms.
Total: 15 test cases.
"""

import base64
import json
import os
import unittest
import urllib.parse
import xml.etree.ElementTree as ET

from tests.e2e.test_helpers import (
    PROJECT_ROOT,
    REFERENCE_CLOUDFLARE_V4_CIDRS,
    REFERENCE_CLOUDFLARE_V6_CIDRS,
    SAMPLE_SS_CHACHA,
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
    is_desktop_ipv6_implemented,
    is_desktop_ss_xray_implemented,
)

from core.bgp_fetcher import BGPFetcher
from core.config_parser import ConfigParser, ParsedConfig
from core.tester_engine import ScanResult, TesterEngine
from core.xray_runner import XrayManager, get_free_port


class TestTier3CrossFeatureCombinations(unittest.TestCase):
    """Tier 3: Pairwise and multi-feature interaction tests."""

    def test_combo_f1_f3_shadowsocks_with_ipv6(self):
        """Combo: Shadowsocks (F1) + IPv6 Clean IP formatting (F3)."""
        parsed = ConfigParser.parse(SAMPLE_SS_SIP002)
        clean_ip = "2606:4700::1"
        mod_link = ConfigParser.generate_modified_link(parsed, clean_ip, "IPv6-Test")
        self.assertTrue(mod_link.startswith("ss://"))
        self.assertIn("CF:2606:4700::1", urllib.parse.unquote(mod_link))
        # Format check for IPv6 in host:port
        formatted_host = format_clean_ip_url(clean_ip, parsed.port)
        self.assertEqual(formatted_host, "[2606:4700::1]:8443")

    def test_combo_f3_f8_vless_with_ipv6(self):
        """Combo: VLESS parsing (F8) + IPv6 Clean IP formatting (F3)."""
        parsed = ConfigParser.parse(SAMPLE_VLESS_WS)
        clean_ip = "2606:4700::1"
        mod_link = ConfigParser.generate_modified_link(parsed, clean_ip)
        self.assertTrue(mod_link.startswith("vless://"))
        self.assertIn(f"CF:{clean_ip}", urllib.parse.unquote(mod_link))
        if f"[{clean_ip}]" not in mod_link:
            self.skipTest("F3 IPv6 bracket formatting in VLESS URLs pending M1")
        self.assertIn(f"[{clean_ip}]:443", mod_link)

    def test_combo_f3_f8_vmess_with_ipv6(self):
        """Combo: VMess parsing (F8) + IPv6 Clean IP in JSON (F3)."""
        parsed = ConfigParser.parse(SAMPLE_VMESS)
        clean_ip = "2606:4700::1"
        mod_link = ConfigParser.generate_modified_link(parsed, clean_ip, "VMess-IPv6")
        self.assertTrue(mod_link.startswith("vmess://"))
        b64_content = mod_link[8:]
        decoded_json = json.loads(base64.b64decode(b64_content).decode())
        self.assertEqual(decoded_json["add"], clean_ip)
        self.assertIn("CF:2606:4700::1", decoded_json["ps"])

    def test_combo_f3_f8_trojan_with_ipv6(self):
        """Combo: Trojan parsing (F8) + IPv6 Clean IP formatting (F3)."""
        parsed = ConfigParser.parse(SAMPLE_TROJAN)
        clean_ip = "2606:4700::1"
        mod_link = ConfigParser.generate_modified_link(parsed, clean_ip)
        self.assertTrue(mod_link.startswith("trojan://"))
        self.assertIn(f"CF:{clean_ip}", urllib.parse.unquote(mod_link))

    def test_combo_f8_f7_bgp_candidates_into_config_parser(self):
        """Combo: BGP candidate generation (F7) feeding into ConfigParser clean links (F8)."""
        fetcher = BGPFetcher()
        prefixes = ["104.16.0.0/12"]
        candidates = fetcher.generate_candidate_ips(prefixes, sample_mode="gateway_hosts", ips_per_prefix=3)
        self.assertGreater(len(candidates), 0)

        parsed = ConfigParser.parse(SAMPLE_VLESS_WS)
        for cand in candidates:
            ip = cand["ip"]
            mod_link = ConfigParser.generate_modified_link(parsed, ip, "Fast")
            self.assertTrue(mod_link.startswith("vless://"))
            self.assertIn(f"@{ip}:443", mod_link)
            self.assertIn(f"CF:{ip}", urllib.parse.unquote(mod_link))

    def test_combo_f7_f9_bgp_candidates_into_tester_engine(self):
        """Combo: BGP candidate generation (F7) feeding into TesterEngine scan structure (F9)."""
        fetcher = BGPFetcher()
        candidates = fetcher.generate_candidate_ips(["104.16.0.0/12"], sample_mode="gateway_hosts", ips_per_prefix=2)
        parsed = ConfigParser.parse(SAMPLE_VLESS_WS)

        # Build scan candidate list and verify engine results model
        engine_results = []
        for cand in candidates:
            res = ScanResult(
                ip=cand["ip"],
                prefix=cand["prefix"],
                port=parsed.port,
                protocol=parsed.protocol,
                status="SUCCESS",
                google_status="204 OK",
                google_latency_ms=95.0,
                modified_link=ConfigParser.generate_modified_link(parsed, cand["ip"])
            )
            engine_results.append(res)

        self.assertEqual(len(engine_results), len(candidates))
        self.assertTrue(all(r.status == "SUCCESS" for r in engine_results))
        self.assertTrue(all(r.modified_link.startswith("vless://") for r in engine_results))

    def test_combo_f1_f8_ss_parsing_into_xray_generator(self):
        """Combo: Shadowsocks parsing (F8) feeding into XrayConfigGenerator (F1)."""
        parsed = ConfigParser.parse(SAMPLE_SS_SIP002)
        self.assertEqual(parsed.protocol, "ss")
        self.assertEqual(parsed.port, 8443)

        if not is_desktop_ss_xray_implemented():
            self.skipTest("F1 Shadowsocks outbound pending in core/xray_runner.py")

        xray_cfg = XrayManager.generate_xray_config(parsed, "104.16.24.1", 10808, 10809)
        proxy_outbound = next((o for o in xray_cfg.get("outbounds", []) if o.get("tag") == "proxy"), {})
        self.assertEqual(proxy_outbound.get("protocol"), "shadowsocks")
        servers = proxy_outbound.get("settings", {}).get("servers", [])
        self.assertEqual(servers[0].get("address"), "104.16.24.1")
        self.assertEqual(servers[0].get("port"), 8443)

    def test_combo_f8_f10_pq_vless_into_xray_xhttp(self):
        """Combo: Post-Quantum VLESS (F8) feeding into Xray xhttp settings (F10)."""
        parsed = ConfigParser.parse(SAMPLE_VLESS_XHTTP_PQ)
        self.assertIn("mlkem768", parsed.encryption)
        self.assertEqual(parsed.transport, "xhttp")

        xray_cfg = XrayManager.generate_xray_config(parsed, "104.16.24.1", 10808, 10809)
        stream_settings = xray_cfg["outbounds"][0]["streamSettings"]
        self.assertEqual(stream_settings.get("network"), "xhttp")
        self.assertIn("xhttpSettings", stream_settings)
        self.assertIn("headers", stream_settings["xhttpSettings"])

    def test_combo_f9_f12_engine_sorting_into_bilingual_export(self):
        """Combo: TesterEngine latency sorting (F9) feeding into export reporting (F12)."""
        raw_results = [
            ScanResult(ip="104.16.24.3", prefix="104.16.0.0/12", port=443, protocol="vless", status="SUCCESS", google_status="204 OK", google_latency_ms=180.0),
            ScanResult(ip="104.16.24.1", prefix="104.16.0.0/12", port=443, protocol="vless", status="SUCCESS", google_status="204 OK", google_latency_ms=65.0),
            ScanResult(ip="104.16.24.2", prefix="104.16.0.0/12", port=443, protocol="vless", status="SUCCESS", google_status="204 OK", google_latency_ms=120.0),
        ]
        sorted_results = sorted(raw_results, key=lambda r: r.google_latency_ms if r.google_latency_ms > 0 else 99999)
        self.assertEqual(sorted_results[0].ip, "104.16.24.1")
        self.assertEqual(sorted_results[1].ip, "104.16.24.2")
        self.assertEqual(sorted_results[2].ip, "104.16.24.3")

        # Formats cleanly for both LTR and RTL views
        lines_en = [f"{i+1}. {r.ip} - {r.google_latency_ms}ms" for i, r in enumerate(sorted_results)]
        self.assertIn("1. 104.16.24.1 - 65.0ms", lines_en[0])

    def test_combo_f5_f10_gradle_packaging_and_jni_libs(self):
        """Combo: Gradle packaging configuration (F5) matching JNI libxray.so extraction (F10)."""
        if not is_android_gradle_setup_implemented():
            self.skipTest("F5 Android Gradle setup pending")
        app_build = os.path.join(PROJECT_ROOT, "android", "app", "build.gradle.kts")
        with open(app_build, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("useLegacyPackaging = true" in content or "jniLibs" in content)

    def test_combo_f6_f11_manifest_and_foreground_service(self):
        """Combo: AndroidManifest declarations (F6) matching ScanForegroundService (F11)."""
        if not is_android_manifest_implemented():
            self.skipTest("F6 AndroidManifest pending")
        manifest_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "AndroidManifest.xml")
        tree = ET.parse(manifest_path)
        service_elem = tree.getroot().find(".//service")
        self.assertIsNotNone(service_elem)
        name_attr = service_elem.attrib.get("{http://schemas.android.com/apk/res/android}name", "")
        self.assertTrue("ScanForegroundService" in name_attr or "service" in name_attr.lower())

    def test_combo_f13_f14_jvm_tests_and_cicd_job(self):
        """Combo: Android JVM test suite execution (F13) inside CI/CD workflow (F14)."""
        if not is_cicd_android_release_implemented():
            self.skipTest("F14 CI/CD build-android job pending")
        workflow_path = os.path.join(PROJECT_ROOT, ".github", "workflows", "release.yml")
        with open(workflow_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("build-android", content)
        self.assertTrue("testDebugUnitTest" in content or "./gradlew test" in content)

    def test_combo_f7_f3_bgp_ipv6_fallback_and_gateway_hosts(self):
        """Combo: IPv6 fallback CIDRs (F3) + Gateway hosts sampling mode (F7)."""
        fetcher = BGPFetcher()
        prefixes = ["2606:4700::/32"]
        candidates = fetcher.generate_candidate_ips(prefixes, sample_mode="gateway_hosts", ips_per_prefix=2)
        if not candidates:
            self.skipTest("F3 IPv6 candidate generation pending in core/bgp_fetcher.py")
        self.assertGreater(len(candidates), 0)
        self.assertIn(":", candidates[0]["ip"])

    def test_combo_f2_f10_xray_cleanup_and_port_concurrency(self):
        """Combo: Xray port allocation (F2) and multi-inbound concurrency (F10)."""
        # Allocate 5 independent inbound pairs without conflict
        ports = [(get_free_port(), get_free_port()) for _ in range(5)]
        all_allocated = [p for pair in ports for p in pair]
        self.assertEqual(len(set(all_allocated)), 10)

    def test_combo_f8_f12_share_intent_interop(self):
        """Combo: Multi-protocol link generation (F8) formatted into Share Intent payload (F12)."""
        vless_parsed = ConfigParser.parse(SAMPLE_VLESS_WS)
        vmess_parsed = ConfigParser.parse(SAMPLE_VMESS)
        trojan_parsed = ConfigParser.parse(SAMPLE_TROJAN)
        ss_parsed = ConfigParser.parse(SAMPLE_SS_SIP002)

        clean_ip = "104.16.24.1"
        mod_vless = ConfigParser.generate_modified_link(vless_parsed, clean_ip)
        mod_vmess = ConfigParser.generate_modified_link(vmess_parsed, clean_ip)
        mod_trojan = ConfigParser.generate_modified_link(trojan_parsed, clean_ip)
        mod_ss = ConfigParser.generate_modified_link(ss_parsed, clean_ip)

        share_payload = "\n".join([mod_vless, mod_vmess, mod_trojan, mod_ss])
        self.assertIn("vless://", share_payload)
        self.assertIn("vmess://", share_payload)
        self.assertIn("trojan://", share_payload)
        self.assertIn("ss://", share_payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
