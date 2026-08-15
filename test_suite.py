"""
Comprehensive Test Suite for Cloudflare Clean IP Scanner
Runs automated tests on:
- BGP Fetcher (HE BGP API)
- Config Parser & Modified Link Generator
- Tester Engine & Real-Time Latency Sorting
- Flask API Endpoints & Export Functionality
"""

import asyncio
import json
import unittest

from app_server import app
from core.bgp_fetcher import BGPFetcher
from core.config_parser import ConfigParser, ParsedConfig
from core.tester_engine import ScanResult, TesterEngine


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
        # Sample base64 vmess
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
        import base64
        vmess_link = "vmess://" + base64.b64encode(b64_str.encode()).decode()
        
        parsed = ConfigParser.parse(vmess_link)
        self.assertEqual(parsed.protocol, "vmess")
        self.assertEqual(parsed.uuid, "11111111-2222-3333-4444-555555555555")
        
        mod_link = ConfigParser.generate_modified_link(parsed, "104.17.25.1", "90ms")
        self.assertTrue(mod_link.startswith("vmess://"))
        # Verify clean IP inside decoded JSON
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
        from core.xray_runner import XrayManager
        cfg_str = 'vless://937afff8-7513-4078-a759-b884b6c2d2ef@203.23.106.70:8443?encryption=mlkem768x25519plus.xorpub.0rtt.Hfz68R2EM_t2U26EoytKVZZv3I2kxQApYvNh2LXEASg&security=tls&sni=cf2.persiana.garden&fp=chrome&alpn=h2%2Chttp%2F1.1&insecure=0&allowInsecure=0&type=xhttp&host=cf.persiana.garden&path=api%2Fv1%2Ftelemetry%2Fmetrics&mode=packet-up&extra=%7B%22headers%22%3A%7B%22Accept-Encoding%22%3A%22gzip%2C%2Bdeflate%2C%2Bbr%2C%2Bzstd%22%2C%22Accept-Language%22%3A%22en-US%2Cen%3Bq%3D0.9%22%2C%22Cache-Control%22%3A%22no-cache%22%2C%22Pragma%22%3A%22no-cache%22%2C%22User-Agent%22%3A%22Mozilla%2F5.0%2B%28Windows%2BNT%2B10.0%3B%2BWin64%3B%2Bx64%29%2BAppleWebKit%2F537.36%2B%28KHTML%2C%2Blike%2BGecko%29%2BChrome%2F126.0.0.0%2BSafari%2F537.36%22%7D%2C%22mode%22%3A%22packet-up%22%2C%22xPaddingBytes%22%3A%22100-1000%22%7D#node'
        parsed = ConfigParser.parse(cfg_str)
        self.assertIn("headers", parsed.extra)
        xray_cfg = XrayManager.generate_xray_config(parsed, "104.16.24.1", 10808, 10809)
        self.assertEqual(xray_cfg["outbounds"][0]["streamSettings"]["network"], "xhttp")
        self.assertIn("xhttpSettings", xray_cfg["outbounds"][0]["streamSettings"])
        self.assertIn("headers", xray_cfg["outbounds"][0]["streamSettings"]["xhttpSettings"])


class TestAppServerAPI(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_index_page(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Cloudflare Clean IP Scanner", res.data)

    def test_fetch_prefixes_api(self):
        res = self.client.post("/api/fetch-prefixes", json={"asn": "13335"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("ipv4", data["data"])

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
