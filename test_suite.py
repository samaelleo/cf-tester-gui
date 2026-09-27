"""
Comprehensive Test Suite for Cloudflare Clean IP Scanner
Runs automated tests on:
- BGP Fetcher (HE BGP API, IPv4/IPv6 Fallback CIDRs, IPv6 Candidate Generation)
- Config Parser (VLESS, VMess, Trojan, Shadowsocks, RFC 3986 Bracket Formatting)
- Tester Engine & Real-Time Latency Sorting
- Xray Configuration Generator (VLESS, VMess, Trojan, Shadowsocks, Cleanup Verification)
- Flask API Endpoints & Export Functionality (including IPv6 start-scan parameter)
"""

import asyncio
import base64
import ipaddress
import json
import os
import re
import unittest
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

from app_server import app
from core.bgp_fetcher import FALLBACK_CLOUDFLARE_V6, BGPFetcher
from core.config_parser import ConfigParser, ParsedConfig
from core.tester_engine import ScanResult, TesterEngine
from core.xray_runner import XrayManager, XrayTester


class TestBGPFetcher(unittest.TestCase):
    def setUp(self):
        self.fetcher = BGPFetcher()

    def test_clean_asn(self):
        self.assertEqual(self.fetcher.clean_asn("AS13335"), "13335")
        self.assertEqual(self.fetcher.clean_asn("as209242"), "209242")
        self.assertEqual(self.fetcher.clean_asn("13335"), "13335")

    def test_fetch_prefixes_he(self):
        res = self.fetcher.fetch_prefixes_from_he("13335")
        self.assertIn(res["status"], ["success", "fallback"])
        self.assertGreater(len(res["ipv4"]), 5)
        self.assertTrue(all("/" in p for p in res["ipv4"][:10]))

    def test_generate_candidate_ips(self):
        prefixes = ["104.16.0.0/12", "172.64.0.0/13", "1.1.1.0/24"]

        # Test random mode
        random_ips = self.fetcher.generate_candidate_ips(prefixes, sample_mode="random", ips_per_prefix=2)
        self.assertGreater(len(random_ips), 0)
        self.assertIn("ip", random_ips[0])
        self.assertIn("prefix", random_ips[0])

        # Test gateway hosts mode (.1, .10, etc.)
        gw_ips = self.fetcher.generate_candidate_ips(prefixes, sample_mode="gateway_hosts", ips_per_prefix=3)
        self.assertGreater(len(gw_ips), 0)

        # Test custom IP list
        custom_input = ["104.16.24.1", "1.1.1.1", "104.16.0.0/30"]
        custom_res = self.fetcher.generate_candidate_ips(prefixes, custom_ip_list=custom_input)
        self.assertGreaterEqual(len(custom_res), 2)

    def test_ipv6_fallback_prefixes(self):
        import urllib.error

        self.assertGreaterEqual(len(FALLBACK_CLOUDFLARE_V6), 7)
        self.assertIn("2606:4700::/32", FALLBACK_CLOUDFLARE_V6)
        self.assertIn("2400:cb00::/32", FALLBACK_CLOUDFLARE_V6)

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("HE API unreachable")):
            res = self.fetcher.fetch_prefixes_from_he("13335")
            self.assertEqual(res["status"], "fallback")
            self.assertIn("ipv6", res)
            self.assertGreaterEqual(len(res["ipv6"]), 7)
            self.assertIn("2606:4700::/32", res["ipv6"])
            self.assertIn("2400:cb00::/32", res["ipv6"])
            self.assertTrue(all(":" in p and "/" in p for p in res["ipv6"]))
            self.assertEqual(res["total_v6"], len(res["ipv6"]))

    def test_generate_candidate_ips_ipv6_all_modes(self):
        prefixes = ["2606:4700::/32", "2400:cb00::/32"]

        # 1. Gateway hosts mode
        gw_ips = self.fetcher.generate_candidate_ips(
            prefixes, sample_mode="gateway_hosts", ips_per_prefix=3
        )
        self.assertGreater(len(gw_ips), 0)
        for item in gw_ips:
            addr = ipaddress.IPv6Address(item["ip"])
            net = ipaddress.IPv6Network(item["prefix"])
            self.assertIn(addr, net)
        gw_ip_strs = [item["ip"] for item in gw_ips]
        self.assertTrue(any(ip.endswith("::1") or ip.endswith(":1") for ip in gw_ip_strs))

        # 2. Random mode (verifies no OverflowError on large /32 range)
        random_ips = self.fetcher.generate_candidate_ips(
            prefixes, sample_mode="random", ips_per_prefix=5
        )
        self.assertGreater(len(random_ips), 0)
        for item in random_ips:
            addr = ipaddress.IPv6Address(item["ip"])
            net = ipaddress.IPv6Network(item["prefix"])
            self.assertIn(addr, net)
        random_ip_strs = [item["ip"] for item in random_ips]
        self.assertEqual(len(set(random_ip_strs)), len(random_ip_strs))

        # 3. Step mode
        step_ips = self.fetcher.generate_candidate_ips(
            prefixes, sample_mode="step", ips_per_prefix=4
        )
        self.assertGreater(len(step_ips), 0)
        for item in step_ips:
            addr = ipaddress.IPv6Address(item["ip"])
            net = ipaddress.IPv6Network(item["prefix"])
            self.assertIn(addr, net)

        # 4. Custom IPv6 list mode (ensures NO freeze or memory exhaustion)
        custom_input = ["2606:4700::1", "2400:cb00::10", "2606:4700::/120"]
        custom_res = self.fetcher.generate_candidate_ips(
            prefixes, custom_ip_list=custom_input, ips_per_prefix=2
        )
        self.assertGreaterEqual(len(custom_res), 3)
        res_ips = [c["ip"] for c in custom_res]
        self.assertIn("2606:4700::1", res_ips)
        self.assertIn("2400:cb00::10", res_ips)


class TestConfigParser(unittest.TestCase):
    def test_vless_parsing_and_generation(self):
        vless_link = "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@myworker.workers.dev:443?type=ws&security=tls&path=%2F%3Fed%3D2560&host=myworker.workers.dev&sni=myworker.workers.dev&fp=chrome#MyNode"
        parsed = ConfigParser.parse(vless_link)
        self.assertEqual(parsed.protocol, "vless")
        self.assertEqual(parsed.uuid, "d342d11e-d424-4583-b36e-524ab1f0afa4")
        self.assertEqual(parsed.port, 443)
        self.assertEqual(parsed.transport, "ws")
        self.assertEqual(parsed.security, "tls")
        self.assertEqual(parsed.sni, "myworker.workers.dev")
        self.assertEqual(parsed.host, "myworker.workers.dev")

        mod_link = ConfigParser.generate_modified_link(parsed, "104.16.24.1", "120ms")
        self.assertTrue(mod_link.startswith("vless://"))
        self.assertIn("@104.16.24.1:443", mod_link)
        self.assertIn("host=myworker.workers.dev", mod_link)
        self.assertIn("sni=myworker.workers.dev", mod_link)

    def test_vmess_parsing_and_generation(self):
        vmess_dict = {
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
        b64_str = json.dumps(vmess_dict)
        vmess_link = "vmess://" + base64.b64encode(b64_str.encode()).decode()

        parsed = ConfigParser.parse(vmess_link)
        self.assertEqual(parsed.protocol, "vmess")
        self.assertEqual(parsed.uuid, "11111111-2222-3333-4444-555555555555")

        mod_link = ConfigParser.generate_modified_link(parsed, "104.17.25.1", "90ms")
        self.assertTrue(mod_link.startswith("vmess://"))
        dec_mod = json.loads(base64.b64decode(mod_link[8:]).decode())
        self.assertEqual(dec_mod["add"], "104.17.25.1")
        self.assertEqual(dec_mod["host"], "orig.domain.com")
        self.assertEqual(dec_mod["sni"], "orig.domain.com")

    def test_trojan_parsing(self):
        trojan_link = "trojan://mypassword123@trojan.domain.com:443?security=tls&sni=trojan.domain.com&type=ws&path=%2Ftr#TrojanTest"
        parsed = ConfigParser.parse(trojan_link)
        self.assertEqual(parsed.protocol, "trojan")
        self.assertEqual(parsed.uuid, "mypassword123")
        self.assertEqual(parsed.sni, "trojan.domain.com")

        mod_link = ConfigParser.generate_modified_link(parsed, "188.114.96.1", "150ms")
        self.assertTrue(mod_link.startswith("trojan://"))
        self.assertIn("@188.114.96.1:443", mod_link)

    def test_ss_sip002_parsing_and_generation(self):
        raw_userinfo = "chacha20-ietf-poly1305:SecretPass123"
        b64_userinfo = base64.urlsafe_b64encode(raw_userinfo.encode()).decode().rstrip("=")
        ss_link = f"ss://{b64_userinfo}@edge.example.com:8388#MySIP002Node"

        parsed = ConfigParser.parse(ss_link)
        self.assertEqual(parsed.protocol, "ss")
        self.assertEqual(parsed.address, "edge.example.com")
        self.assertEqual(parsed.port, 8388)
        self.assertEqual(parsed.tag, "MySIP002Node")

        import urllib.parse
        mod_link = ConfigParser.generate_modified_link(parsed, "104.16.24.1", "55ms")
        self.assertTrue(mod_link.startswith("ss://"))
        self.assertIn("@104.16.24.1:8388", mod_link)
        self.assertIn("CF:104.16.24.1", urllib.parse.unquote(mod_link))
        self.assertIn("[55ms]", urllib.parse.unquote(mod_link))

    def test_ss_legacy_base64_parsing_and_generation(self):
        raw_full = "aes-256-gcm:LegacyPass!@20.200.0.1:8443"
        b64_full = base64.b64encode(raw_full.encode()).decode()
        ss_link = f"ss://{b64_full}#MyLegacyNode"

        parsed = ConfigParser.parse(ss_link)
        self.assertEqual(parsed.protocol, "ss")
        self.assertEqual(parsed.address, "20.200.0.1")
        self.assertEqual(parsed.port, 8443)
        self.assertEqual(parsed.tag, "MyLegacyNode")

        mod_link = ConfigParser.generate_modified_link(parsed, "104.17.32.1", "80ms")
        self.assertTrue(mod_link.startswith("ss://"))
        self.assertIn("@104.17.32.1:8443", mod_link)

    def test_ipv6_clean_ip_link_regeneration_brackets(self):
        import urllib.parse
        clean_ipv6 = "2606:4700::1"

        # 1. VLESS bracket formatting
        vless_link = "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@orig.domain:443?type=ws&security=tls#VlessNode"
        parsed_vless = ConfigParser.parse(vless_link)
        mod_vless = ConfigParser.generate_modified_link(parsed_vless, clean_ipv6, "110ms")
        self.assertIn("@[2606:4700::1]:443", mod_vless)
        p_vless = urllib.parse.urlparse(mod_vless)
        self.assertEqual(p_vless.hostname, "2606:4700::1")
        self.assertEqual(p_vless.port, 443)

        # 2. Trojan bracket formatting
        trojan_link = "trojan://mypassword@orig.domain:443?security=tls#TrojanNode"
        parsed_trojan = ConfigParser.parse(trojan_link)
        mod_trojan = ConfigParser.generate_modified_link(parsed_trojan, clean_ipv6, "95ms")
        self.assertIn("@[2606:4700::1]:443", mod_trojan)
        p_trojan = urllib.parse.urlparse(mod_trojan)
        self.assertEqual(p_trojan.hostname, "2606:4700::1")
        self.assertEqual(p_trojan.port, 443)

        # 3. Shadowsocks bracket formatting
        ss_link = "ss://chacha20-ietf-poly1305:pass@orig.domain:8388#SSNode"
        parsed_ss = ConfigParser.parse(ss_link)
        mod_ss = ConfigParser.generate_modified_link(parsed_ss, clean_ipv6, "70ms")
        self.assertIn("@[2606:4700::1]:8388", mod_ss)
        p_ss = urllib.parse.urlparse(mod_ss)
        self.assertEqual(p_ss.hostname, "2606:4700::1")
        self.assertEqual(p_ss.port, 8388)

        # 4. Direct hostname bracket formatting
        parsed_direct = ConfigParser.parse("cp.cloudflare.com:443")
        mod_direct = ConfigParser.generate_modified_link(parsed_direct, clean_ipv6)
        self.assertIn("[2606:4700::1]:443", mod_direct)


class TestTesterEngineAndSorting(unittest.TestCase):
    def test_engine_latency_sorting(self):
        engine = TesterEngine()
        cfg = ConfigParser.parse("cp.cloudflare.com:443")

        test_ips = [
            {"ip": "104.16.24.1", "prefix": "104.16.0.0/12"},
            {"ip": "104.17.32.1", "prefix": "104.17.32.0/20"},
            {"ip": "1.1.1.1", "prefix": "1.1.1.0/24"},
            {"ip": "188.114.96.1", "prefix": "188.114.96.0/20"}
        ]

        results = asyncio.run(engine.run_scan(test_ips, cfg, concurrency=4, timeout_sec=4.0))
        # If network is online, verify sorting
        if len(results) > 1:
            for i in range(len(results) - 1):
                lat_a = results[i].google_latency_ms if results[i].google_latency_ms > 0 else 99999
                lat_b = results[i+1].google_latency_ms if results[i+1].google_latency_ms > 0 else 99999
                self.assertLessEqual(lat_a, lat_b, f"Results not properly sorted: {lat_a} > {lat_b}")

    def test_realdelay_config_generation(self):
        cfg_str = 'vless://937afff8-7513-4078-a759-b884b6c2d2ef@203.23.106.70:8443?encryption=mlkem768x25519plus.xorpub.0rtt.Hfz68R2EM_t2U26EoytKVZZv3I2kxQApYvNh2LXEASg&security=tls&sni=cf2.persiana.garden&fp=chrome&alpn=h2%2Chttp%2F1.1&insecure=0&allowInsecure=0&type=xhttp&host=cf.persiana.garden&path=api%2Fv1%2Ftelemetry%2Fmetrics&mode=packet-up&extra=%7B%22headers%22%3A%7B%22Accept-Encoding%22%3A%22gzip%2C%2Bdeflate%2C%2Bbr%2C%2Bzstd%22%2C%22Accept-Language%22%3A%22en-US%2Cen%3Bq%3D0.9%22%2C%22Cache-Control%22%3A%22no-cache%22%2C%22Pragma%22%3A%22no-cache%22%2C%22User-Agent%22%3A%22Mozilla%2F5.0%2B%28Windows%2BNT%2B10.0%3B%2BWin64%3B%2Bx64%29%2BAppleWebKit%2F537.36%2B%28KHTML%2C%2Blike%2BGecko%29%2BChrome%2F126.0.0.0%2BSafari%2F537.36%22%7D%2C%22mode%22%3A%22packet-up%22%2C%22xPaddingBytes%22%3A%22100-1000%22%7D#node'
        parsed = ConfigParser.parse(cfg_str)
        self.assertIn("headers", parsed.extra)
        xray_cfg = XrayManager.generate_xray_config(parsed, "104.16.24.1", 10808, 10809)
        self.assertEqual(xray_cfg["outbounds"][0]["streamSettings"]["network"], "xhttp")
        self.assertIn("xhttpSettings", xray_cfg["outbounds"][0]["streamSettings"])
        self.assertIn("headers", xray_cfg["outbounds"][0]["streamSettings"]["xhttpSettings"])

    def test_ss_xray_config_generation(self):
        raw_userinfo = "chacha20-ietf-poly1305:SecretPass123"
        b64_userinfo = base64.urlsafe_b64encode(raw_userinfo.encode()).decode()
        ss_link = f"ss://{b64_userinfo}@edge.example.com:8388#SSNode"
        parsed = ConfigParser.parse(ss_link)

        xray_cfg = XrayManager.generate_xray_config(parsed, "104.16.24.1", 10808, 10809)

        proxy_outbound = next((o for o in xray_cfg["outbounds"] if o.get("tag") == "proxy"), None)
        self.assertIsNotNone(proxy_outbound)
        self.assertEqual(proxy_outbound["protocol"], "shadowsocks")

        servers = proxy_outbound["settings"]["servers"]
        self.assertEqual(len(servers), 1)
        server = servers[0]
        self.assertEqual(server["address"], "104.16.24.1")
        self.assertEqual(server["port"], 8388)
        self.assertEqual(server["method"], "chacha20-ietf-poly1305")
        self.assertEqual(server["password"], "SecretPass123")
        self.assertFalse(server.get("ota", True))

        self.assertEqual(proxy_outbound["streamSettings"]["network"], "tcp")
        self.assertEqual(proxy_outbound["streamSettings"]["security"], "none")
        self.assertEqual(xray_cfg["inbounds"][0]["port"], 10808)
        self.assertEqual(xray_cfg["inbounds"][1]["port"], 10809)

    def test_xray_cleanup_no_duplicate(self):
        xray_path = os.path.join(os.path.dirname(__file__), "core", "xray_runner.py")
        with open(xray_path, "r", encoding="utf-8") as f:
            content = f.read()
        pattern = r"if os\.path\.exists\(tmp_cfg_path\):\s*try:\s*os\.remove\(tmp_cfg_path\)"
        matches = len(re.findall(pattern, content))
        self.assertEqual(matches, 1, f"Expected exactly 1 cleanup block in test_single_realdelay, found {matches}")

    def test_xray_tester_temp_file_cleanup_on_success_and_error(self):
        cfg = ConfigParser.parse("vless://uuid@domain.com:443?type=ws&security=tls#Node")
        clean_ip = "104.16.24.1"

        mock_writer = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch.object(XrayManager, "get_xray_path", return_value="dummy_xray_bin"), \
             patch("builtins.open", mock_open()), \
             patch("os.path.exists", return_value=True), \
             patch("subprocess.Popen") as mock_popen, \
             patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn, \
             patch("urllib.request.build_opener") as mock_opener, \
             patch("os.remove") as mock_remove:

            mock_conn.return_value = (MagicMock(), mock_writer)

            # Case A: Success execution cleanup
            mock_proc = MagicMock()
            mock_popen.return_value = mock_proc

            mock_resp = MagicMock()
            mock_resp.status = 204
            mock_open_ctx = MagicMock()
            mock_open_ctx.__enter__.return_value = mock_resp
            mock_opener.return_value.open.return_value = mock_open_ctx

            res = asyncio.run(XrayTester.test_single_realdelay(cfg, clean_ip, timeout_sec=0.5))
            self.assertEqual(res["status"], "SUCCESS")

            tmp_removals = [call for call in mock_remove.call_args_list if "xray_tmp_" in str(call)]
            self.assertEqual(len(tmp_removals), 1, f"Expected 1 temp file remove call, got {len(tmp_removals)}")

            # Case B: Exception execution cleanup (verifies finally block)
            mock_popen.side_effect = RuntimeError("Process execution failure")
            mock_remove.reset_mock()

            res_err = asyncio.run(XrayTester.test_single_realdelay(cfg, clean_ip, timeout_sec=0.5))
            self.assertEqual(res_err["status"], "FAILED")

            tmp_removals_err = [call for call in mock_remove.call_args_list if "xray_tmp_" in str(call)]
            self.assertEqual(len(tmp_removals_err), 1, "Temp file must be removed in finally block on error")


class TestAppServerAPI(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_index_page(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Cloudflare Clean IP Scanner", res.data)
        res.close()

    def test_fetch_prefixes_api(self):
        res = self.client.post("/api/fetch-prefixes", json={"asn": "13335"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("ipv4", data["data"])
        self.assertIn("ipv6", data["data"])

    def test_parse_config_api(self):
        vless_link = "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@myworker.workers.dev:443?type=ws&security=tls&path=%2F#Node1"
        res = self.client.post("/api/parse-config", json={"config": vless_link})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["parsed"]["protocol"], "vless")

    def test_export_api(self):
        sample_results = [
            {
                "ip": "104.16.24.1",
                "prefix": "104.16.0.0/12",
                "google_latency_ms": 120.5,
                "tcp_latency_ms": 25.0,
                "tls_latency_ms": 60.0,
                "google_status": "204 OK",
                "modified_link": "vless://...104.16.24.1..."
            }
        ]

        # Test TXT IPs export
        res_ips = self.client.post("/api/export", json={"format": "ips", "results": sample_results})
        self.assertEqual(res_ips.status_code, 200)
        self.assertIn(b"104.16.24.1", res_ips.data)

        # Test CSV export
        res_csv = self.client.post("/api/export", json={"format": "csv", "results": sample_results})
        self.assertEqual(res_csv.status_code, 200)
        self.assertIn(b"104.16.24.1", res_csv.data)

    def test_start_scan_api_ipv6_selection(self):
        payload = {
            "asn": "13335",
            "ip_version": "ipv6",
            "sample_mode": "gateway_hosts",
            "ips_per_prefix": 1,
            "max_total_ips": 5
        }
        res = self.client.post("/api/start-scan", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("Scan started", data["message"])
        # Stop scan
        self.client.post("/api/stop-scan")


if __name__ == "__main__":
    unittest.main(verbosity=2)
