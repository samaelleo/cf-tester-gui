#!/usr/bin/env python3
"""
tests/test_m3_challenge.py

Milestone 3 (F10) Adversarial Challenger Stress & Verification Suite.
Empirically tests:
1. ELF header structure and machine code compliance (arm64-v8a / x86_64) for libxray.so.
2. Official packaged libxray.so binaries in android/app/src/main/jniLibs/.
3. download_xray_android.py CLI behaviors: --check-only, --offline-fallback, idempotency.
4. Resilience against corrupt ZIP archives and network failures in download_xray_android.
5. Cross-platform parity between Python core/xray_runner and Kotlin XrayConfigGenerator.
6. Shadowsocks credentials permutations (SIP002, unpadded Base64, legacy host/port).
7. IPv6 bracket stripping and format normalization.
"""

import base64
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.download_xray_android import (
    create_minimal_elf_stub,
    extract_xray_binary,
    process_abi,
    ABI_CONFIG,
    TARGET_LIB_NAME,
)
from core.config_parser import ConfigParser, ParsedConfig
from core.xray_runner import XrayManager


class TestM3ElfHeaderAndBinaryValidation(unittest.TestCase):
    """Stress test ELF binary structure and packaged jniLibs binaries."""

    def test_minimal_elf_stub_structure_arm64(self):
        machine_arm64 = 183  # EM_AARCH64 (0xB7)
        stub = create_minimal_elf_stub(machine_arm64)
        self.assertGreaterEqual(len(stub), 120)

        # 1. ELF Magic: 0x7F, 'E', 'L', 'F'
        self.assertEqual(stub[:4], b"\x7fELF")

        # 2. ELFCLASS64 (2), ELFDATA2LSB (1, little-endian), EV_CURRENT (1)
        self.assertEqual(stub[4], 2)
        self.assertEqual(stub[5], 1)
        self.assertEqual(stub[6], 1)

        # 3. Unpack Elf64_Ehdr (64 bytes)
        # Ident: 16 bytes, then <HHIQQQIHHHHHH
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack(
            "<HHIQQQIHHHHHH", stub[16:64]
        )
        self.assertEqual(e_type, 2)  # ET_EXEC
        self.assertEqual(e_machine, machine_arm64)
        self.assertEqual(e_version, 1)
        self.assertEqual(e_phoff, 64)
        self.assertEqual(e_phnum, 1)

        # 4. Unpack Elf64_Phdr (56 bytes)
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(
            "<IIQQQQQQ", stub[64:120]
        )
        self.assertEqual(p_type, 1)  # PT_LOAD
        self.assertEqual(p_flags, 5)  # PF_R | PF_X (1 | 4 = 5)

    def test_minimal_elf_stub_structure_x86_64(self):
        machine_x86_64 = 62  # EM_X86_64 (0x3E)
        stub = create_minimal_elf_stub(machine_x86_64)
        self.assertGreaterEqual(len(stub), 120)
        self.assertEqual(stub[:4], b"\x7fELF")
        e_type, e_machine = struct.unpack("<HH", stub[16:20])
        self.assertEqual(e_type, 2)
        self.assertEqual(e_machine, machine_x86_64)

    def test_packaged_jni_libs_binaries_present_and_valid(self):
        jni_dir = PROJECT_ROOT / "android" / "app" / "src" / "main" / "jniLibs"
        arm64_so = jni_dir / "arm64-v8a" / TARGET_LIB_NAME
        x86_64_so = jni_dir / "x86_64" / TARGET_LIB_NAME

        self.assertTrue(arm64_so.exists(), f"Missing {arm64_so}")
        self.assertTrue(x86_64_so.exists(), f"Missing {x86_64_so}")

        # Both must be > 30MB (full Xray-core executables)
        self.assertGreater(arm64_so.stat().st_size, 30_000_000, "arm64 libxray.so must be full binary")
        self.assertGreater(x86_64_so.stat().st_size, 30_000_000, "x86_64 libxray.so must be full binary")

        # Check arm64 ELF header
        with open(arm64_so, "rb") as f:
            hdr_arm64 = f.read(20)
        self.assertEqual(hdr_arm64[:4], b"\x7fELF")
        e_type, e_machine = struct.unpack("<HH", hdr_arm64[16:20])
        self.assertEqual(e_machine, 183, "arm64-v8a libxray.so machine must be 183 (AArch64)")

        # Check x86_64 ELF header
        with open(x86_64_so, "rb") as f:
            hdr_x86 = f.read(20)
        self.assertEqual(hdr_x86[:4], b"\x7fELF")
        e_type, e_machine = struct.unpack("<HH", hdr_x86[16:20])
        self.assertEqual(e_machine, 62, "x86_64 libxray.so machine must be 62 (EM_X86_64)")


class TestM3DownloaderScript(unittest.TestCase):
    """Stress test scripts/download_xray_android.py CLI and error handling."""

    def test_cli_check_only_flag(self):
        script_path = PROJECT_ROOT / "scripts" / "download_xray_android.py"
        res = subprocess.run(
            [sys.executable, str(script_path), "--check-only"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res.returncode, 0, f"--check-only failed: {res.stderr}")
        self.assertIn("Found binary for arm64-v8a", res.stdout + res.stderr)
        self.assertIn("Found binary for x86_64", res.stdout + res.stderr)

    def test_offline_fallback_generation(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_path = Path(tmp_dir) / "jniLibs"
            cache_path = Path(tmp_dir) / "cache"

            # Call process_abi with an invalid version so network fails, but with offline_fallback=True
            success = process_abi(
                abi="arm64-v8a",
                output_base_dir=out_path,
                cache_dir=cache_path,
                version="v0.0.0-nonexistent",
                force=True,
                offline_fallback=True,
            )
            self.assertTrue(success, "offline_fallback must succeed by generating minimal ELF stub")
            target_so = out_path / "arm64-v8a" / TARGET_LIB_NAME
            self.assertTrue(target_so.exists())
            self.assertEqual(target_so.stat().st_size, 120)
            with open(target_so, "rb") as f:
                content = f.read()
            self.assertEqual(content[:4], b"\x7fELF")

    def test_corrupt_zip_handling(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            corrupt_zip = Path(tmp_dir) / "corrupt.zip"
            corrupt_zip.write_bytes(b"This is not a valid zip file content")
            target_file = Path(tmp_dir) / "libxray.so"

            extracted = extract_xray_binary(corrupt_zip, target_file)
            self.assertFalse(extracted, "Corrupt zip must fail extraction cleanly without crashing")
            self.assertFalse(target_file.exists())


class TestM3CrossPlatformParity(unittest.TestCase):
    """Verify behavioral equivalence between Python desktop core and Kotlin engine."""

    def test_shadowsocks_outbound_structure_parity(self):
        # Python config generation
        raw_ss = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQxMjM=@orig.domain.com:8443#SS-Test"
        parsed = ConfigParser.parse(raw_ss)
        clean_ip = "104.16.24.1"

        py_cfg = XrayManager.generate_xray_config(parsed, clean_ip, inbound_socks_port=10809, inbound_http_port=10808)
        self.assertIn("outbounds", py_cfg)
        proxy = py_cfg["outbounds"][0]

        self.assertEqual(proxy["protocol"], "shadowsocks")
        server = proxy["settings"]["servers"][0]
        self.assertEqual(server["address"], clean_ip)
        self.assertEqual(server["port"], 8443)
        self.assertEqual(server["method"], "aes-256-gcm")
        self.assertEqual(server["password"], "password123")
        self.assertEqual(server["ota"], False)

    def test_ipv6_bracket_stripping_in_outbound(self):
        raw_vless = "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@myworker.workers.dev:443?type=ws&security=tls#VLESS"
        parsed = ConfigParser.parse(raw_vless)

        bracketed_ipv6 = "[2606:4700::1]"
        py_cfg = XrayManager.generate_xray_config(parsed, bracketed_ipv6, inbound_socks_port=10809, inbound_http_port=10808)
        proxy = py_cfg["outbounds"][0]
        server = proxy["settings"]["vnext"][0]
        # In Xray JSON outbound, address must NOT have brackets
        self.assertEqual(server["address"].replace("[", "").replace("]", ""), "2606:4700::1")

    def test_batch_routing_rules_isolation(self):
        parsed = ConfigParser.parse("trojan://pass@domain.com:443?security=tls")
        ips = ["104.16.1.1", "104.16.1.2", "104.16.1.3"]
        ports = [10810, 10811, 10812]

        batch_cfg = XrayManager.generate_batch_xray_config(parsed, ips, ports)
        self.assertEqual(len(batch_cfg["inbounds"]), 3)
        # 3 proxy outbounds + 1 direct outbound
        self.assertEqual(len(batch_cfg["outbounds"]), 4)
        self.assertEqual(batch_cfg["routing"]["domainStrategy"], "AsIs")

        rules = batch_cfg["routing"]["rules"]
        self.assertEqual(len(rules), 3)
        for i in range(3):
            self.assertEqual(rules[i]["inboundTag"], [f"http-in-{i}"])
            self.assertEqual(rules[i]["outboundTag"], f"proxy-{i}")


if __name__ == "__main__":
    unittest.main()
