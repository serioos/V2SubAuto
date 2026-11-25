using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using V2SubAuto.Models;

namespace V2SubAuto.Services
{
    public sealed class CoreProcessInstance : IDisposable
    {
        private readonly Process _process;
        private readonly string _tempConfigPath;
        private readonly IReadOnlyCollection<int>? _leasedPorts;
        private bool _disposed;

        public CoreProcessInstance(Process process, string tempConfigPath, IReadOnlyCollection<int>? leasedPorts = null)
        {
            _process = process;
            _tempConfigPath = tempConfigPath;
            _leasedPorts = leasedPorts;
        }

        public bool HasExited
        {
            get
            {
                try { return _process.HasExited; } catch { return true; }
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            try
            {
                if (!_process.HasExited)
                {
                    _process.Kill(entireProcessTree: true);
                    _process.WaitForExit(1000);
                }
            }
            catch
            {
                // Best-effort cleanup
            }
            finally
            {
                try { _process.Dispose(); } catch { }
                try
                {
                    if (File.Exists(_tempConfigPath))
                        File.Delete(_tempConfigPath);
                }
                catch { }
                PortAllocator.ReleasePorts(_leasedPorts);
            }
        }
    }

    public sealed class CoreProcessRunner : IDisposable
    {
        private readonly string _tempDirectory;
        private readonly IntPtr _jobHandle;
        private static readonly Regex AnsiEscapeRegex = new(@"\x1B\[[0-9;]*[A-Za-z]", RegexOptions.Compiled);
        private bool _disposed;

        public CoreProcessRunner(string baseDirectory)
        {
            _tempDirectory = Path.Combine(baseDirectory, "temp");
            Directory.CreateDirectory(_tempDirectory);
            _jobHandle = OperatingSystem.IsWindows() ? CreateKillOnCloseJobObject() : IntPtr.Zero;
        }

        public async Task<(CoreProcessInstance? Instance, string? ErrorMessage)> StartCoreAsync(
            CoreEngineType coreType,
            string executablePath,
            string jsonConfig,
            int probePort,
            CancellationToken ct,
            IReadOnlyCollection<int>? leasedPorts = null,
            int nodeCount = 1,
            int firstProbePort = 0)
        {
            if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
            {
                PortAllocator.ReleasePorts(leasedPorts);
                return (null, $"Executable not found: {executablePath}");
            }

            string? configPath = null;
            Process? proc = null;

            try
            {
                Directory.CreateDirectory(_tempDirectory);
                configPath = Path.Combine(_tempDirectory, $"test_{coreType}_{Guid.NewGuid():N}.json");
                await File.WriteAllTextAsync(configPath, jsonConfig, ct).ConfigureAwait(false);

                var psi = new ProcessStartInfo
                {
                    FileName = executablePath,
                    WorkingDirectory = Path.GetDirectoryName(executablePath) ?? AppContext.BaseDirectory,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                psi.ArgumentList.Add("run");
                psi.ArgumentList.Add("-c");
                psi.ArgumentList.Add(configPath);

                var outputLock = new object();
                string? fatalLine = null;
                string? lastNonWarningLine = null;
                var stdoutDone = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                var stderrDone = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

                void AppendOutput(string? line)
                {
                    if (string.IsNullOrWhiteSpace(line)) return;
                    var trimmed = AnsiEscapeRegex.Replace(line, string.Empty).Trim();

                    // Ignore Xray deprecation warnings so they never drown out real startup errors
                    if (trimmed.Contains("[Warning]", StringComparison.OrdinalIgnoreCase))
                        return;

                    lock (outputLock)
                    {
                        lastNonWarningLine = trimmed;
                        if (trimmed.Contains("Failed to start", StringComparison.OrdinalIgnoreCase) ||
                            trimmed.Contains("infra/conf", StringComparison.OrdinalIgnoreCase) ||
                            trimmed.Contains("FATAL", StringComparison.OrdinalIgnoreCase))
                        {
                            fatalLine = trimmed;
                        }
                    }
                }

                proc = new Process { StartInfo = psi, EnableRaisingEvents = false };
                proc.ErrorDataReceived += (_, e) =>
                {
                    if (e.Data == null) stderrDone.TrySetResult(true);
                    else AppendOutput(e.Data);
                };
                proc.OutputDataReceived += (_, e) =>
                {
                    if (e.Data == null) stdoutDone.TrySetResult(true);
                    else AppendOutput(e.Data);
                };

                if (!proc.Start())
                {
                    proc.Dispose();
                    TryDelete(configPath);
                    PortAllocator.ReleasePorts(leasedPorts);
                    return (null, "Process failed to start.");
                }

                if (_jobHandle != IntPtr.Zero)
                {
                    try { AssignProcessToJobObject(_jobHandle, proc.Handle); } catch { }
                }

                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();

                // Fast readiness polling (15ms loop, scaled deadline for large batches, probing both first and last inbounds)
                int startupBudgetMs = Math.Clamp(2500 + nodeCount * 8, 2500, 6000);
                var deadline = Stopwatch.StartNew();
                bool firstReady = firstProbePort <= 0 || firstProbePort == probePort;
                bool lastReady = probePort <= 0;

                while (deadline.ElapsedMilliseconds < startupBudgetMs)
                {
                    ct.ThrowIfCancellationRequested();

                    if (proc.HasExited)
                    {
                        var err = await CaptureExitErrorAsync(proc, stdoutDone.Task, stderrDone.Task, outputLock, () => fatalLine, () => lastNonWarningLine).ConfigureAwait(false);
                        proc.Dispose();
                        TryDelete(configPath);
                        PortAllocator.ReleasePorts(leasedPorts);
                        return (null, err);
                    }

                    if (!firstReady && await IsLocalPortListeningAsync(firstProbePort, ct).ConfigureAwait(false))
                    {
                        firstReady = true;
                    }

                    if (!lastReady && await IsLocalPortListeningAsync(probePort, ct).ConfigureAwait(false))
                    {
                        lastReady = true;
                    }

                    if (firstReady && lastReady)
                    {
                        // Brief settle window for large multi-inbound batches where inbounds bind concurrently
                        if (nodeCount > 50)
                        {
                            await Task.Delay(40, ct).ConfigureAwait(false);
                        }
                        break;
                    }

                    await Task.Delay(15, ct).ConfigureAwait(false);
                }

                if (proc.HasExited)
                {
                    var err = await CaptureExitErrorAsync(proc, stdoutDone.Task, stderrDone.Task, outputLock, () => fatalLine, () => lastNonWarningLine).ConfigureAwait(false);
                    proc.Dispose();
                    TryDelete(configPath);
                    PortAllocator.ReleasePorts(leasedPorts);
                    return (null, err);
                }

                if ((!firstReady || !lastReady) && probePort > 0)
                {
                    KillAndWait(proc);
                    var err = await CaptureExitErrorAsync(proc, stdoutDone.Task, stderrDone.Task, outputLock, () => fatalLine, () => lastNonWarningLine).ConfigureAwait(false);
                    proc.Dispose();
                    TryDelete(configPath);
                    PortAllocator.ReleasePorts(leasedPorts);
                    return (null, $"Core did not open port {probePort} within {startupBudgetMs}ms ({err})");
                }

                return (new CoreProcessInstance(proc, configPath, leasedPorts), null);
            }
            catch (OperationCanceledException)
            {
                KillAndWait(proc);
                try { proc?.Dispose(); } catch { }
                if (configPath != null) TryDelete(configPath);
                PortAllocator.ReleasePorts(leasedPorts);
                throw;
            }
            catch (Exception ex)
            {
                KillAndWait(proc);
                try { proc?.Dispose(); } catch { }
                if (configPath != null) TryDelete(configPath);
                PortAllocator.ReleasePorts(leasedPorts);
                return (null, ex.Message);
            }
        }

        private static void KillAndWait(Process? proc)
        {
            if (proc == null) return;
            try
            {
                if (!proc.HasExited)
                {
                    proc.Kill(entireProcessTree: true);
                    proc.WaitForExit(1000);
                }
            }
            catch { }
        }

        private static async Task<string> CaptureExitErrorAsync(
            Process proc,
            Task stdoutDone,
            Task stderrDone,
            object outputLock,
            Func<string?> getFatal,
            Func<string?> getLast)
        {
            int exitCode = -1;
            try
            {
                // Wait briefly for async stdout/stderr callbacks to finish draining
                await Task.WhenAny(Task.WhenAll(stdoutDone, stderrDone), Task.Delay(400)).ConfigureAwait(false);
                if (proc.HasExited)
                {
                    exitCode = proc.ExitCode;
                }
            }
            catch { }

            lock (outputLock)
            {
                return getFatal() ?? getLast() ?? $"Core exited with code {exitCode}";
            }
        }

        private static async Task<bool> IsLocalPortListeningAsync(int port, CancellationToken ct)
        {
            try
            {
                using var tcp = new TcpClient();
                using var probeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                probeCts.CancelAfter(60);
                await tcp.ConnectAsync("127.0.0.1", port, probeCts.Token).ConfigureAwait(false);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public void CleanupTempDirectory()
        {
            try
            {
                if (!Directory.Exists(_tempDirectory)) return;
                foreach (var file in Directory.GetFiles(_tempDirectory, "test_*.json"))
                {
                    TryDelete(file);
                }
            }
            catch { }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (_jobHandle != IntPtr.Zero)
            {
                try { CloseHandle(_jobHandle); } catch { }
            }
        }

        private static void TryDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); } catch { }
        }

        // =====================================================================
        // Win32 Job Object (KILL_ON_JOB_CLOSE) to prevent orphaned core processes
        // =====================================================================
        private const int JobObjectExtendedLimitInformationClass = 9;
        private const uint JobObjectLimitKillOnJobClose = 0x00002000;

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(
            IntPtr hJob,
            int infoType,
            ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInfo,
            uint cbJobObjectInfoLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        private static IntPtr CreateKillOnCloseJobObject()
        {
            try
            {
                var handle = CreateJobObject(IntPtr.Zero, null);
                if (handle == IntPtr.Zero) return IntPtr.Zero;

                var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
                {
                    BasicLimitInformation = new JOBOBJECT_BASIC_LIMIT_INFORMATION
                    {
                        LimitFlags = JobObjectLimitKillOnJobClose
                    }
                };

                uint length = (uint)Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
                if (!SetInformationJobObject(handle, JobObjectExtendedLimitInformationClass, ref info, length))
                {
                    CloseHandle(handle);
                    return IntPtr.Zero;
                }

                return handle;
            }
            catch
            {
                return IntPtr.Zero;
            }
        }
    }
}
