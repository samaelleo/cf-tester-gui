#!/usr/bin/env python3
"""
scripts/download_xray_android.py

Downloads and packages official Xray-core Android binaries for clean IP latency
and RealDelay scanning on Android (W^X / API 29+ compliant).

Targets:
  - arm64-v8a -> Xray-android-arm64-v8a.zip -> libxray.so
  - x86_64    -> Xray-android-amd64.zip     -> libxray.so

Destination:
  android/app/src/main/jniLibs/{abi}/libxray.so

Features:
  - Idempotent: Skips download if libxray.so is already present and non-empty.
  - Offline / CI fallback: Generates valid minimal 64-bit ELF binary stubs if
    offline or download fails when --offline-fallback is active.
  - Retries with exponential backoff on transient network errors.
  - Zero third-party dependencies (pure standard library).
"""

import argparse
import hashlib
import io
import logging
import os
import shutil
import stat
import struct
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("download_xray_android")

# Project root calculation: scripts/..
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
DEFAULT_JNILIBS_DIR = PROJECT_ROOT / "android" / "app" / "src" / "main" / "jniLibs"
DEFAULT_CACHE_DIR = PROJECT_ROOT / ".cache" / "xray"

# Official XTLS/Xray-core release asset mappings
ABI_CONFIG: Dict[str, Dict[str, object]] = {
    "arm64-v8a": {
        "asset": "Xray-android-arm64-v8a.zip",
        "elf_machine": 183,  # EM_AARCH64 (0xB7)
        "description": "Android 64-bit ARM (aarch64)",
    },
    "x86_64": {
        "asset": "Xray-android-amd64.zip",
        "elf_machine": 62,  # EM_X86_64 (0x3E)
        "description": "Android 64-bit x86_64 (amd64)",
    },
}

DEFAULT_ABIS = ["arm64-v8a", "x86_64"]
TARGET_LIB_NAME = "libxray.so"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36 cf-tester-downloader/1.0"
)


def create_minimal_elf_stub(machine_code: int) -> bytes:
    """
    Constructs a structurally valid, minimal 64-bit ELF executable header.
    Used as an offline/CI fallback so Android Gradle Packaging (AAPT2)
    and unit tests succeed without requiring a 45MB remote binary download.
    """
    # 16 bytes e_ident: 0x7f, 'E', 'L', 'F', ELFCLASS64 (2), ELFDATA2LSB (1), EV_CURRENT (1), ELFOSABI_NONE (0)
    e_ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)

    # Elf64_Ehdr (64 bytes total)
    header = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,             # e_type: ET_EXEC
        machine_code,  # e_machine: 183 (arm64) or 62 (x86_64)
        1,             # e_version: EV_CURRENT
        0x400000,      # e_entry: virtual address
        64,            # e_phoff: program header table offset
        0,             # e_shoff: section header table offset
        0,             # e_flags
        64,            # e_ehsize: ELF header size
        56,            # e_phentsize: program header entry size
        1,             # e_phnum: 1 program header entry
        0,             # e_shentsize
        0,             # e_shnum
        0,             # e_shstrndx
    )

    # Elf64_Phdr (56 bytes total) - PT_LOAD segment with PF_R | PF_X
    p_header = struct.pack(
        "<IIQQQQQQ",
        1,             # p_type: PT_LOAD
        5,             # p_flags: PF_R | PF_X (Read + Execute)
        0,             # p_offset: segment file offset
        0x400000,      # p_vaddr: segment virtual address
        0x400000,      # p_paddr: segment physical address
        120,           # p_filesz: 64 + 56 = 120 bytes
        120,           # p_memsz
        0x1000,        # p_align: 4KB page align
    )

    return header + p_header


def get_download_url(version: str, asset_name: str) -> str:
    """Builds release download URL for GitHub releases."""
    if version.lower() == "latest":
        return f"https://github.com/XTLS/Xray-core/releases/latest/download/{asset_name}"
    tag = version if version.startswith("v") else f"v{version}"
    return f"https://github.com/XTLS/Xray-core/releases/download/{tag}/{asset_name}"


def download_with_retry(
    url: str,
    dest_path: Path,
    max_retries: int = 3,
    timeout_sec: int = 30,
) -> bool:
    """Downloads a remote file with streaming and exponential backoff retry."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

    for attempt in range(1, max_retries + 1):
        try:
            logger.info("Downloading %s (attempt %d/%d)...", url, attempt, max_retries)
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_dest = dest_path.with_suffix(".tmp")

            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                if resp.status != 200:
                    raise urllib.error.HTTPError(
                        url, resp.status, f"HTTP {resp.status}", resp.headers, None
                    )
                with open(tmp_dest, "wb") as f_out:
                    shutil.copyfileobj(resp, f_out, length=64 * 1024)

            # Atomic rename on completion
            if dest_path.exists():
                dest_path.unlink()
            tmp_dest.rename(dest_path)
            logger.info("Successfully downloaded: %s (%d bytes)", dest_path.name, dest_path.stat().st_size)
            return True

        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
            logger.warning("Download error on attempt %d: %s", attempt, exc)
            if attempt < max_retries:
                sleep_time = attempt * 2
                logger.info("Retrying in %d seconds...", sleep_time)
                time.sleep(sleep_time)

    return False


def extract_xray_binary(zip_path: Path, target_file: Path) -> bool:
    """
    Extracts the 'xray' binary executable from the downloaded ZIP archive
    and writes it to target_file (libxray.so), setting executable permissions.
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            # Xray archives contain 'xray'
            matching = [name for name in z.namelist() if name.rstrip() in ("xray", "xray.exe")]
            if not matching:
                logger.error("No 'xray' binary found in %s. Namelist: %s", zip_path.name, z.namelist())
                return False

            binary_member = matching[0]
            logger.info("Extracting '%s' from %s -> %s...", binary_member, zip_path.name, target_file)
            target_file.parent.mkdir(parents=True, exist_ok=True)

            with z.open(binary_member) as src, open(target_file, "wb") as dst:
                shutil.copyfileobj(src, dst, length=64 * 1024)

        # Ensure executable permissions (0755: rwxr-xr-x)
        try:
            current_mode = os.stat(target_file).st_mode
            os.chmod(target_file, current_mode | stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        except OSError:
            pass  # Windows file systems may ignore POSIX chmod bits

        logger.info("Extracted %s (size: %d bytes)", target_file, target_file.stat().st_size)
        return True

    except Exception as exc:
        logger.error("Failed to extract %s: %s", zip_path.name, exc)
        return False


def process_abi(
    abi: str,
    output_base_dir: Path,
    cache_dir: Path,
    version: str,
    force: bool,
    offline_fallback: bool,
) -> bool:
    """Processes download and extraction for a single ABI."""
    cfg = ABI_CONFIG.get(abi)
    if not cfg:
        logger.error("Unsupported ABI '%s'. Supported: %s", abi, list(ABI_CONFIG.keys()))
        return False

    target_dir = output_base_dir / abi
    target_so = target_dir / TARGET_LIB_NAME
    target_dir.mkdir(parents=True, exist_ok=True)

    # Check if already present
    if not force and target_so.exists() and target_so.stat().st_size > 100:
        logger.info("Binary %s already exists (%d bytes). Use --force to re-download.", target_so, target_so.stat().st_size)
        return True

    asset_name = str(cfg["asset"])
    url = get_download_url(version, asset_name)
    cached_zip = cache_dir / f"{version}_{asset_name}"

    download_success = False

    # Check local cache first
    if cached_zip.exists() and cached_zip.stat().st_size > 1000 and not force:
        logger.info("Using cached archive: %s", cached_zip)
        download_success = True
    else:
        # Download from GitHub
        download_success = download_with_retry(url, cached_zip)

    # Extract binary if download succeeded
    if download_success and cached_zip.exists():
        if extract_xray_binary(cached_zip, target_so):
            return True
        logger.warning("Extraction from %s failed. Trying fallback if permitted.", cached_zip)

    # Handle offline fallback or failure
    if offline_fallback or os.environ.get("XRAY_OFFLINE_FALLBACK") == "1":
        logger.warning(
            "Generating minimal ELF stub for %s (ABI: %s) because download was unavailable.",
            target_so,
            abi,
        )
        stub_bytes = create_minimal_elf_stub(int(cfg["elf_machine"]))
        with open(target_so, "wb") as f_stub:
            f_stub.write(stub_bytes)

        try:
            os.chmod(target_so, 0o755)
        except OSError:
            pass
        return True

    logger.error("Failed to acquire %s for %s and --offline-fallback was not specified.", TARGET_LIB_NAME, abi)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download and package Android Xray-core binaries (libxray.so) for clean IP latency testing."
    )
    parser.add_argument(
        "--abis",
        type=str,
        default=",".join(DEFAULT_ABIS),
        help=f"Comma-separated list of target ABIs (default: {','.join(DEFAULT_ABIS)})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_JNILIBS_DIR,
        help=f"Target jniLibs root directory (default: {DEFAULT_JNILIBS_DIR})",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_CACHE_DIR,
        help=f"Cache directory for downloaded archives (default: {DEFAULT_CACHE_DIR})",
    )
    parser.add_argument(
        "--version",
        type=str,
        default="latest",
        help="Xray release tag to download (default: 'latest')",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-download even if libxray.so already exists",
    )
    parser.add_argument(
        "--offline-fallback",
        action="store_true",
        default=bool(os.environ.get("XRAY_OFFLINE_FALLBACK", False)),
        help="Generate valid ELF stub binaries if remote download fails (ideal for CI/offline builds)",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Check whether libxray.so exists for all specified ABIs without downloading",
    )

    args = parser.parse_args()
    abis = [a.strip() for a in args.abis.split(",") if a.strip()]

    if args.check_only:
        all_present = True
        for abi in abis:
            lib_path = args.output_dir / abi / TARGET_LIB_NAME
            if not lib_path.exists() or lib_path.stat().st_size == 0:
                logger.info("Missing binary for %s: %s", abi, lib_path)
                all_present = False
            else:
                logger.info("Found binary for %s: %s (%d bytes)", abi, lib_path, lib_path.stat().st_size)
        return 0 if all_present else 1

    logger.info("Processing Android Xray binaries for ABIs: %s", abis)
    logger.info("Output directory: %s", args.output_dir)

    success_count = 0
    for abi in abis:
        if process_abi(
            abi=abi,
            output_base_dir=args.output_dir,
            cache_dir=args.cache_dir,
            version=args.version,
            force=args.force,
            offline_fallback=args.offline_fallback,
        ):
            success_count += 1

    if success_count == len(abis):
        logger.info("All %d ABIs processed successfully.", len(abis))
        return 0

    logger.error("Only %d of %d ABIs were processed successfully.", success_count, len(abis))
    return 1


if __name__ == "__main__":
    sys.exit(main())
