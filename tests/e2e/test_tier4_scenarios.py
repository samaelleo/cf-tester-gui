"""
Tier 4: Real-World Application Scenarios Test Suite
Covers 8 end-to-end realistic user workflows matching real-world operational scenarios.
Total: 8 test cases.
"""

import base64
import json
import os
import unittest
from unittest.mock import patch
import urllib.parse
import xml.etree.ElementTree as ET

from tests.e2e.test_helpers import (
    PROJECT_ROOT,
    REFERENCE_CLOUDFLARE_V4_CIDRS,
    REFERENCE_CLOUDFLARE_V6_CIDRS,
    SAMPLE_SS_SIP002,
    SAMPLE_TROJAN,
    SAMPLE_VLESS_WS,
    SAMPLE_VLESS_XHTTP_PQ,
    SAMPLE_VMESS,
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

from app_server import app
from core.bgp_fetcher import BGPFetcher
from core.config_parser import ConfigParser, ParsedConfig
from core.tester_engine import ScanResult, TesterEngine
from core.xray_runner import XrayManager, get_free_port


class TestTier4RealWorldScenarios(unittest.TestCase):
    """Tier 4: 8 Comprehensive User Workflows."""

    def test_scenario_1_desktop_scan_workflow(self):
        """Scenario 1: Desktop user scans AS13335 with VLESS+WS and exports CSV."""
        app.config["TESTING"] = True
        client = app.test_client()

        # Step 1: User parses VLESS configuration
        res_parse = client.post("/api/parse-config", json={"config": SAMPLE_VLESS_WS})
        self.assertEqual(res_parse.status_code, 200)
        parsed_data = res_parse.get_json()["parsed"]
        self.assertEqual(parsed_data["protocol"], "vless")

        # Step 2: Fetch prefixes for AS13335
        fetcher = BGPFetcher()
        prefixes_res = fetcher.fetch_prefixes_from_he("13335")
        self.assertIn(prefixes_res["status"], ["success", "fallback"])
        self.assertGreater(len(prefixes_res["ipv4"]), 0)

        # Step 3: Sample candidate IPs using gateway hosts
        candidates = fetcher.generate_candidate_ips(
            prefixes=prefixes_res["ipv4"][:5],
            sample_mode="gateway_hosts",
            ips_per_prefix=2
        )
        self.assertGreater(len(candidates), 0)

        # Step 4: Simulate scan results and sort by latency
        scan_results = []
        for idx, cand in enumerate(candidates):
            latency = 60.0 + (idx * 15.0)
            res = ScanResult(
                ip=cand["ip"],
                prefix=cand["prefix"],
                port=443,
                protocol="vless",
                status="SUCCESS",
                google_status="204 OK",
                google_latency_ms=latency,
                modified_link=f"vless://uuid@{cand['ip']}:443"
            )
            scan_results.append(res.to_dict())

        # Step 5: Export results to CSV
        res_export = client.post("/api/export", json={"format": "csv", "results": scan_results})
        self.assertEqual(res_export.status_code, 200)
        self.assertIn(b"Rank,IP,Prefix,Google_Latency_ms", res_export.data)
        self.assertIn(candidates[0]["ip"].encode(), res_export.data)

    def test_scenario_2_mobile_background_scan_workflow(self):
        """Scenario 2: Mobile user initiates scan, app transitions to Foreground Service."""
        if not is_android_manifest_implemented() or not is_android_service_implemented():
            self.skipTest("Android Foreground Service components pending implementation")

        # Step 1: Verify Manifest permissions for background execution
        manifest_path = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "AndroidManifest.xml")
        tree = ET.parse(manifest_path)
        perms = [elem.attrib.get("{http://schemas.android.com/apk/res/android}name", "") for elem in tree.getroot().findall("uses-permission")]
        self.assertIn("android.permission.FOREGROUND_SERVICE", perms)
        self.assertIn("android.permission.WAKE_LOCK", perms)

        # Step 2: Verify Foreground Service declaration
        service_elem = tree.getroot().find(".//service")
        self.assertIsNotNone(service_elem)
        fgs_type = service_elem.attrib.get("{http://schemas.android.com/apk/res/android}foregroundServiceType", "")
        self.assertIn("specialUse", fgs_type)

        # Step 3: Verify Service class implements WakeLock and Stop action
        srv_file = os.path.join(PROJECT_ROOT, "android", "app", "src", "main", "java", "com", "cftester", "scanner", "service", "ScanForegroundService.kt")
        with open(srv_file, "r", encoding="utf-8") as f:
            code = f.read()
        self.assertTrue("WakeLock" in code or "PARTIAL_WAKE_LOCK" in code)
        self.assertTrue("stop" in code.lower())

    def test_scenario_3_shadowsocks_migration_workflow(self):
        """Scenario 3: User imports Shadowsocks link, generates clean links and Xray config."""
        # Step 1: Parse SIP002 Shadowsocks link
        parsed = ConfigParser.parse(SAMPLE_SS_SIP002)
        self.assertEqual(parsed.protocol, "ss")
        self.assertEqual(parsed.port, 8443)

        # Step 2: Generate candidate IPs
        fetcher = BGPFetcher()
        candidates = fetcher.generate_candidate_ips(["104.16.0.0/12"], sample_mode="gateway_hosts", ips_per_prefix=2)
        self.assertGreater(len(candidates), 0)

        # Step 3: Generate modified clean links
        best_ip = candidates[0]["ip"]
        mod_link = ConfigParser.generate_modified_link(parsed, best_ip, "Clean-SS")
        self.assertTrue(mod_link.startswith("ss://"))
        self.assertIn(f"@{best_ip}:8443", mod_link)

        # Step 4: Verify Xray outbound configuration
        if not is_desktop_ss_xray_implemented():
            self.skipTest("F1 Shadowsocks outbound pending M1 implementation")
        xray_cfg = XrayManager.generate_xray_config(parsed, best_ip, 10808, 10809)
        proxy = next(o for o in xray_cfg["outbounds"] if o.get("tag") == "proxy")
        self.assertEqual(proxy["protocol"], "shadowsocks")

    def test_scenario_4_post_quantum_xhttp_high_security_workflow(self):
        """Scenario 4: User imports Post-Quantum VLESS with xhttp transport."""
        # Step 1: Parse PQ VLESS link
        parsed = ConfigParser.parse(SAMPLE_VLESS_XHTTP_PQ)
        self.assertEqual(parsed.protocol, "vless")
        self.assertIn("mlkem768", parsed.encryption)
        self.assertEqual(parsed.transport, "xhttp")
        self.assertIn("headers", parsed.extra)

        # Step 2: Generate clean IP modified link
        clean_ip = "104.16.24.1"
        mod_link = ConfigParser.generate_modified_link(parsed, clean_ip, "PQ-Clean")
        self.assertTrue(mod_link.startswith("vless://"))
        self.assertIn("encryption=mlkem768", mod_link)
        self.assertIn("mode=packet-up", mod_link)

        # Step 3: Verify Xray config preserves xhttp headers and PQ settings
        xray_cfg = XrayManager.generate_xray_config(parsed, clean_ip, 10808, 10809)
        outbound = xray_cfg["outbounds"][0]
        self.assertEqual(outbound["streamSettings"]["network"], "xhttp")
        self.assertIn("headers", outbound["streamSettings"]["xhttpSettings"])
        users = outbound["settings"]["vnext"][0]["users"]
        self.assertEqual(users[0]["encryption"], parsed.encryption)

    def test_scenario_5_offline_api_fallback_disaster_recovery(self):
        """Scenario 5: BGP API is offline/blocked; scanner seamlessly switches to fallback CIDRs."""
        fetcher = BGPFetcher()

        # Simulate API network outage
        with patch("urllib.request.urlopen", side_effect=Exception("HE BGP API Connection Timed Out")):
            result = fetcher.fetch_prefixes_from_he("13335")
            self.assertEqual(result["status"], "fallback")
            self.assertGreaterEqual(len(result["ipv4"]), 15)
            self.assertEqual(result["source"], "Local Fallback List")

            # Scanner continues generating candidates without interruption
            candidates = fetcher.generate_candidate_ips(result["ipv4"], sample_mode="random", max_total_ips=10)
            self.assertEqual(len(candidates), 10)
            self.assertTrue(all(c["ip"].startswith("1") for c in candidates))

    def test_scenario_6_realdelay_verification_workflow(self):
        """Scenario 6: RealDelay testing pipeline with ephemeral ports and proxy request."""
        parsed = ConfigParser.parse(SAMPLE_VLESS_WS)
        clean_ip = "104.16.24.1"

        # Allocate ephemeral ports
        socks_port = get_free_port()
        http_port = get_free_port()
        self.assertNotEqual(socks_port, http_port)

        # Generate Xray configuration pointing to clean IP
        cfg = XrayManager.generate_xray_config(
            parsed=parsed,
            clean_ip=clean_ip,
            inbound_socks_port=socks_port,
            inbound_http_port=http_port
        )
        self.assertEqual(cfg["inbounds"][0]["port"], socks_port)
        self.assertEqual(cfg["inbounds"][1]["port"], http_port)
        self.assertEqual(cfg["outbounds"][0]["settings"]["vnext"][0]["address"], clean_ip)

    def test_scenario_7_proxy_app_interoperability_and_share_intent(self):
        """Scenario 7: Share clean configs directly to third-party proxy apps (v2rayNG / NekoBox)."""
        configs = [SAMPLE_VLESS_WS, SAMPLE_VMESS, SAMPLE_TROJAN, SAMPLE_SS_SIP002]
        clean_ips = ["104.16.24.1", "104.17.32.1", "172.64.0.1", "188.114.96.1"]

        export_links = []
        for raw_cfg, ip in zip(configs, clean_ips):
            parsed = ConfigParser.parse(raw_cfg)
            mod_link = ConfigParser.generate_modified_link(parsed, ip, "Fast")
            export_links.append(mod_link)

        # Verify all links formatted properly for Share Intent
        bundle = "\n\n".join(export_links)
        self.assertIn("vless://", bundle)
        self.assertIn("vmess://", bundle)
        self.assertIn("trojan://", bundle)
        self.assertIn("ss://", bundle)

    def test_scenario_8_automated_cicd_release_workflow(self):
        """Scenario 8: CI/CD Release pipeline validates build matrix and APK compilation."""
        workflow_path = os.path.join(PROJECT_ROOT, ".github", "workflows", "release.yml")
        self.assertTrue(os.path.exists(workflow_path))
        with open(workflow_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Step 1: Version tag generation
        self.assertIn("version-tag:", content)

        # Step 2: Multi-platform desktop matrix
        self.assertIn("windows-latest", content)
        self.assertIn("ubuntu-latest", content)
        self.assertIn("macos-latest", content)

        # Step 3: Android build verification (when implemented in M5)
        if not is_cicd_android_release_implemented():
            self.skipTest("M5 build-android CI/CD job pending implementation")
        self.assertIn("build-android:", content)
        self.assertIn(".apk", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
