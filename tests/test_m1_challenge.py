"""
Milestone 1 Empirical Challenger Stress & Verification Test Suite
Executes deep boundary, stress, and adversarial testing against:
1. Shadowsocks parsing & outbound generation (special chars, ciphers, SIP002 vs legacy)
2. IPv6 candidate generation (edge CIDRs, extreme counts, step strides, custom lists)
3. IPv6 bracket formatting (RFC 3986 & VMess JSON across all protocols, round-trip parsing)
4. Xray batch config generation (1, 5, 20, 50 clean IPs, port mapping, Xray-core test validation)
"""

import base64
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from typing import Any, Dict, List, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.bgp_fetcher import BGPFetcher
from core.config_parser import ConfigParser, ParsedConfig
from core.xray_runner import XrayManager


class TestShadowsocksChallenger(unittest.TestCase):
    """Stress-test Shadowsocks parsing and outbound generation."""

    CIPHERS = [
        "aes-256-gcm",
        "chacha20-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "aes-128-gcm",
    ]

    def test_ss_ciphers_outbound_generation(self):
        """Verify various standard and 2022 ciphers are correctly extracted into Xray config."""
        for cipher in self.CIPHERS:
            pw = "test_password_123"
            userinfo = base64.b64encode(f"{cipher}:{pw}".encode()).decode()
            link = f"ss://{userinfo}@1.1.1.1:8443#node_{cipher}"
            parsed = ConfigParser.parse(link)
            self.assertEqual(parsed.protocol, "ss")

            method, parsed_pw = XrayManager._parse_ss_credentials(parsed.uuid)
            self.assertEqual(method, cipher, f"Failed cipher extraction for {cipher}")
            self.assertEqual(parsed_pw, pw, f"Failed password extraction for {cipher}")

            cfg = XrayManager.generate_xray_config(parsed, "104.16.1.1", 10808, 10809)
            proxy_out = next(o for o in cfg["outbounds"] if o["tag"] == "proxy")
            self.assertEqual(proxy_out["protocol"], "shadowsocks")
            server = proxy_out["settings"]["servers"][0]
            self.assertEqual(server["address"], "104.16.1.1")
            self.assertEqual(server["port"], 8443)
            self.assertEqual(server["method"], cipher)
            self.assertEqual(server["password"], pw)

    def test_ss_sip002_base64_variants(self):
        """Test SIP002 with padded, unpadded, standard, and urlsafe Base64."""
        cipher = "aes-256-gcm"
        pw = "complex_pw_123"
        payload = f"{cipher}:{pw}".encode()

        variants = [
            base64.b64encode(payload).decode(),
            base64.b64encode(payload).decode().rstrip("="),
            base64.urlsafe_b64encode(payload).decode(),
            base64.urlsafe_b64encode(payload).decode().rstrip("="),
        ]

        for b64_str in variants:
            link = f"ss://{b64_str}@example.com:443#tag"
            parsed = ConfigParser.parse(link)
            method, parsed_pw = XrayManager._parse_ss_credentials(parsed.uuid)
            self.assertEqual(method, cipher)
            self.assertEqual(parsed_pw, pw)

    def test_ss_passwords_with_special_chars(self):
        """
        Challenge edge-case passwords with special characters:
        Colons, equal signs, slashes, pluses, spaces, non-ASCII, and '@'.
        """
        cipher = "aes-256-gcm"
        test_passwords = [
            "simplepassword",
            "pass:with:colons",
            "pass=with=equals==",
            "pass/with/slashes/",
            "pass+with+plus+",
            "pass with spaces",
            "p@ssword",           # Contains @ (triggers truncation bug in SIP002)
            "user@domain.com",    # Contains @ (triggers truncation bug in SIP002)
            "رمز_عبور_فارسی_123", # UTF-8 non-ASCII
        ]

        for pw in test_passwords:
            # 1. SIP002
            sip002_b64 = base64.b64encode(f"{cipher}:{pw}".encode("utf-8")).decode()
            link_sip002 = f"ss://{sip002_b64}@1.1.1.1:443#sip002"
            p_sip002 = ConfigParser.parse(link_sip002)
            m1, pw1 = XrayManager._parse_ss_credentials(p_sip002.uuid)
            self.assertEqual(m1, cipher)
            self.assertEqual(pw1, pw, f"SIP002 password mismatch for {pw!r}: extracted {pw1!r}")

            # 2. Legacy Base64
            legacy_b64 = base64.b64encode(f"{cipher}:{pw}@1.1.1.1:443".encode("utf-8")).decode()
            link_legacy = f"ss://{legacy_b64}#legacy"
            p_legacy = ConfigParser.parse(link_legacy)
            m2, pw2 = XrayManager._parse_ss_credentials(p_legacy.uuid)
            self.assertEqual(m2, cipher)
            self.assertEqual(pw2, pw, f"Legacy Base64 password mismatch for {pw!r}: extracted {pw2!r}")


class TestIPv6CandidateGenerationChallenger(unittest.TestCase):
    """Stress-test IPv6 candidate generation with boundary CIDRs and edge parameters."""

    def setUp(self):
        self.fetcher = BGPFetcher()

    def test_ipv6_various_cidrs_and_modes(self):
        """Test candidate generation across /120, /64, /32, and ::/0."""
        test_cidrs = [
            "2606:4700::/120",  # 256 hosts
            "2606:4700::/64",   # Standard subnet
            "2606:4700::/32",   # Cloudflare allocation
            "::/0",             # Entire address space
        ]
        modes = ["random", "gateway_hosts", "step", "all"]

        for cidr in test_cidrs:
            net = ipaddress.IPv6Network(cidr, strict=False)
            for mode in modes:
                cands = self.fetcher.generate_candidate_ips(
                    [cidr], sample_mode=mode, ips_per_prefix=5, max_total_ips=10
                )
                self.assertGreater(len(cands), 0, f"No candidates generated for {cidr} with mode {mode}")
                self.assertLessEqual(len(cands), 10)

                for c in cands:
                    ip_str = c["ip"]
                    ip_obj = ipaddress.IPv6Address(ip_str)
                    self.assertIn(ip_obj, net, f"Generated IP {ip_str} not in CIDR {cidr}")

    def test_ipv6_slash_128_edge_case(self):
        """
        Challenge /128 single-host prefix.
        Verify that /128 yields the exact host across sampling modes.
        """
        cidr_128 = "2606:4700::1/128"
        for mode in ["random", "gateway_hosts", "step", "all"]:
            cands = self.fetcher.generate_candidate_ips([cidr_128], sample_mode=mode, ips_per_prefix=1)
            self.assertGreater(len(cands), 0, f"/128 CIDR generated 0 candidates in {mode} mode")
            self.assertEqual(cands[0]["ip"], "2606:4700::1", f"/128 CIDR IP mismatch in {mode} mode")

    def test_ipv6_custom_ip_list_slash_128(self):
        """
        Challenge /128 single-host in custom_ip_list.
        Must generate the exact IP '2606:4700::1', not '2606:4700::2' (out-of-subnet).
        """
        res = self.fetcher.generate_candidate_ips([], custom_ip_list=["2606:4700::1/128"])
        self.assertGreater(len(res), 0, "No candidates generated for custom /128")
        self.assertEqual(res[0]["ip"], "2606:4700::1", f"Custom /128 generated out-of-subnet IP: {res[0]['ip']}")

    def test_ipv6_extreme_counts_and_empty_lists(self):
        """Test with extreme counts, zero, negative, empty lists."""
        cidr = "2606:4700::/32"

        # Empty prefix list
        self.assertEqual(self.fetcher.generate_candidate_ips([]), [])

        # max_total_ips = 0
        self.assertEqual(self.fetcher.generate_candidate_ips([cidr], max_total_ips=0), [])

        # max_total_ips negative
        self.assertEqual(self.fetcher.generate_candidate_ips([cidr], max_total_ips=-5), [])

        # ips_per_prefix = 1000 on /120 (which only has 256 addresses)
        cands_small = self.fetcher.generate_candidate_ips(
            ["2606:4700::/120"], sample_mode="random", ips_per_prefix=1000, max_total_ips=5000
        )
        self.assertLessEqual(len(cands_small), 256)
        unique_ips = set(c["ip"] for c in cands_small)
        self.assertEqual(len(unique_ips), len(cands_small))

    def test_ipv6_custom_ip_list_boundaries(self):
        """Test custom_ip_list with exact IPs, subnets, and boundary /128."""
        custom_input = [
            "2606:4700::1",          # Direct IP
            "2606:4700::/120",       # IPv6 subnet
            "104.16.1.1",            # IPv4 direct
            "104.16.0.0/30",         # IPv4 subnet
            "invalid_ip_format",     # Invalid format (should be skipped)
            "",                      # Empty string (should be skipped)
        ]
        res = self.fetcher.generate_candidate_ips([], custom_ip_list=custom_input, ips_per_prefix=3)
        self.assertGreater(len(res), 0)
        ips = [r["ip"] for r in res]
        self.assertIn("2606:4700::1", ips)
        self.assertIn("104.16.1.1", ips)
        for ip in ips:
            ipaddress.ip_address(ip)


class TestIPv6BracketFormattingChallenger(unittest.TestCase):
    """Stress-test IPv6 bracket formatting across all proxy types and raw worker URLs."""

    def test_bracket_formatting_all_protocols(self):
        """Test VLESS, VMess, Trojan, SS, and Direct with raw and bracketed IPv6."""
        vless_raw = "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws&security=tls#VLESS-Node"
        trojan_raw = "trojan://password123@example.com:443?type=ws&security=tls#Trojan-Node"
        ss_raw = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:443#SS-Node"
        direct_raw = "example.com:443"

        vmess_dict = {
            "v": "2", "ps": "VMess-Node", "add": "example.com", "port": 443,
            "id": "11111111-2222-3333-4444-555555555555", "net": "ws", "tls": "tls"
        }
        vmess_raw = f"vmess://{base64.b64encode(json.dumps(vmess_dict).encode()).decode()}"

        configs = {
            "vless": ConfigParser.parse(vless_raw),
            "vmess": ConfigParser.parse(vmess_raw),
            "trojan": ConfigParser.parse(trojan_raw),
            "ss": ConfigParser.parse(ss_raw),
            "direct": ConfigParser.parse(direct_raw),
        }

        test_ips = ["2606:4700::1", "[2606:4700::1]"]

        for proto_name, parsed in configs.items():
            for test_ip in test_ips:
                mod_link = ConfigParser.generate_modified_link(parsed, test_ip)

                if proto_name == "vmess":
                    self.assertTrue(mod_link.startswith("vmess://"))
                    b64_part = mod_link[8:]
                    b64_part += "=" * ((4 - len(b64_part) % 4) % 4)
                    decoded_vmess = json.loads(base64.b64decode(b64_part).decode())
                    self.assertEqual(decoded_vmess["add"], "2606:4700::1", "VMess 'add' should be unbracketed")
                    self.assertNotIn("[", decoded_vmess["add"])
                elif proto_name in ["vless", "trojan", "ss"]:
                    self.assertIn("@[2606:4700::1]:443", mod_link, f"Failed bracket formatting in {proto_name}")
                    parsed_url = urllib.parse.urlsplit(mod_link)
                    self.assertEqual(parsed_url.hostname, "2606:4700::1")
                    self.assertEqual(parsed_url.port, 443)

                    reparsed = ConfigParser.parse(mod_link)
                    self.assertEqual(reparsed.protocol, proto_name)
                    self.assertEqual(reparsed.address, "2606:4700::1")
                    self.assertEqual(reparsed.port, 443)
                elif proto_name == "direct":
                    self.assertTrue(mod_link.startswith("[2606:4700::1]:443"))


class TestXrayBatchConfigChallenger(unittest.TestCase):
    """Stress-test generate_batch_xray_config with 1, 5, 20, 50 clean IPs across protocols."""

    def setUp(self):
        self.xray_path = XrayManager.get_xray_path()
        self.xray_available = os.path.exists(self.xray_path)

    def _validate_config_with_xray_core(self, config_dict: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate config structure using official xray.exe run -test -c."""
        if not self.xray_available:
            return True, "Xray binary not available for validation"

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(config_dict, f)
            tmp_path = f.name

        try:
            res = subprocess.run(
                [self.xray_path, "run", "-test", "-c", tmp_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            is_valid = (res.returncode == 0)
            err_msg = res.stderr or res.stdout
            return is_valid, err_msg
        except Exception as e:
            return False, str(e)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_batch_config_sizes_and_protocols(self):
        """Test generate_batch_xray_config with 1, 5, 20, 50 clean IPs across all 4 protocols."""
        protocols = {
            "vless": ConfigParser.parse("vless://11111111-2222-3333-4444-555555555555@cf.example.com:443?type=ws&security=tls#vless"),
            "vmess": ConfigParser.parse("vmess://" + base64.b64encode(json.dumps({"add":"cf.example.com","port":443,"id":"11111111-2222-3333-4444-555555555555","net":"ws","tls":"tls"}).encode()).decode()),
            "trojan": ConfigParser.parse("trojan://secure_password@cf.example.com:443?type=ws&security=tls#trojan"),
            "ss": ConfigParser.parse("ss://" + base64.b64encode(b"aes-256-gcm:secure_ss_pass").decode() + "@cf.example.com:443#ss"),
        }

        counts = [1, 5, 20, 50]

        for proto_name, parsed_cfg in protocols.items():
            for n in counts:
                clean_ips = [f"104.16.{i // 256}.{i % 256 + 1}" if i % 2 == 0 else f"2606:4700::{i+1}" for i in range(n)]
                ports = [20000 + i for i in range(n)]

                batch_cfg = XrayManager.generate_batch_xray_config(
                    parsed=parsed_cfg,
                    clean_ips=clean_ips,
                    inbound_http_ports=ports
                )

                self.assertIn("inbounds", batch_cfg)
                self.assertIn("outbounds", batch_cfg)
                self.assertIn("routing", batch_cfg)

                self.assertEqual(len(batch_cfg["inbounds"]), n)
                self.assertEqual(len(batch_cfg["outbounds"]), n + 1)
                self.assertEqual(len(batch_cfg["routing"]["rules"]), n)

                for i in range(n):
                    inb = batch_cfg["inbounds"][i]
                    self.assertEqual(inb["tag"], f"http-in-{i}")
                    self.assertEqual(inb["port"], ports[i])
                    self.assertEqual(inb["protocol"], "http")

                    outb = batch_cfg["outbounds"][i]
                    self.assertEqual(outb["tag"], f"proxy-{i}")

                    expected_ip = clean_ips[i]
                    if proto_name in ["vless", "vmess"]:
                        self.assertEqual(outb["settings"]["vnext"][0]["address"], expected_ip)
                    elif proto_name in ["trojan", "ss"]:
                        self.assertEqual(outb["settings"]["servers"][0]["address"], expected_ip)

                    rule = batch_cfg["routing"]["rules"][i]
                    self.assertEqual(rule["inboundTag"], [f"http-in-{i}"])
                    self.assertEqual(rule["outboundTag"], f"proxy-{i}")

                if self.xray_available:
                    valid, err = self._validate_config_with_xray_core(batch_cfg)
                    self.assertTrue(valid, f"Xray-core validation failed for {proto_name} with {n} IPs:\n{err}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
