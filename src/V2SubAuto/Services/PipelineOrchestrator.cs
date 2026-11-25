using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using V2SubAuto.Models;

namespace V2SubAuto.Services
{
    public sealed class PipelineOrchestrator : IDisposable
    {
        private const int MaxSubscriptionBytes = 25 * 1024 * 1024; // 25 MB safety cap

        private readonly SettingsService _settingsService;
        private readonly SpeedtestEngine _speedtest;
        private readonly LocalSubscriptionServer _server;
        private readonly CoreProcessRunner _runner;

        private readonly SemaphoreSlim _runLock = new(1, 1);
        private readonly object _snapshotLock = new();
        private readonly object _stateLock = new();
        private CancellationTokenSource? _currentRunCts;
        private CancellationTokenSource? _schedulerCts;
        private volatile bool _disposed;

        private AppSettings _settings;
        private PipelineSnapshot _snapshot = new();
        private List<ProxyNode> _survivingNodes = new();

        public event Action<PipelineSnapshot>? OnSnapshotChanged;
        public event Action<IReadOnlyList<ProxyNode>>? OnSurvivingNodesChanged;
        public event Action<string>? OnLog;

        public PipelineSnapshot CurrentSnapshot
        {
            get
            {
                lock (_snapshotLock) return _snapshot;
            }
        }

        public IReadOnlyList<ProxyNode> SurvivingNodes => _survivingNodes;

        public PipelineOrchestrator(
            AppSettings settings,
            SettingsService settingsService,
            SpeedtestEngine speedtest,
            LocalSubscriptionServer server,
            CoreProcessRunner runner)
        {
            _settings = settings.Clone();
            _settingsService = settingsService;
            _speedtest = speedtest;
            _server = server;
            _runner = runner;
        }

        public void InitializeCachedState(int servingCount, DateTime? lastCompletedUtc)
        {
            UpdateSnapshot(prev => prev with
            {
                FinalSurvivingCount = Math.Max(0, servingCount),
                LastCompletedUtc = lastCompletedUtc,
                DetailMessage = servingCount > 0
                    ? $"Serving {servingCount} cached configs at {_server.SubscriptionUrl}"
                    : prev.DetailMessage
            });
        }

        public void UpdateSettings(AppSettings settings)
        {
            Volatile.Write(ref _settings, settings.Clone());
            RestartScheduler();
        }

        public void StartScheduler()
        {
            RestartScheduler();
        }

        public void RestartScheduler()
        {
            if (_disposed) return;

            CancellationToken ct;
            bool autoScheduleEnabled;

            lock (_stateLock)
            {
                if (_disposed) return;

                try { _schedulerCts?.Cancel(); } catch { }
                try { _schedulerCts?.Dispose(); } catch { }
                _schedulerCts = null;

                autoScheduleEnabled = Volatile.Read(ref _settings).AutoScheduleEnabled;
                if (!autoScheduleEnabled)
                {
                    ct = CancellationToken.None;
                }
                else
                {
                    _schedulerCts = new CancellationTokenSource();
                    ct = _schedulerCts.Token;
                }
            }

            if (!autoScheduleEnabled)
            {
                UpdateSnapshot(s => s with { NextScheduledUtc = null });
                return;
            }

            _ = Task.Run(async () =>
            {
                while (!ct.IsCancellationRequested && !_disposed)
                {
                    var currentSettings = Volatile.Read(ref _settings);
                    var interval = TimeSpan.FromMinutes(Math.Max(1, currentSettings.RefreshIntervalMinutes));
                    UpdateSnapshot(s => s with { NextScheduledUtc = DateTime.UtcNow.Add(interval) });

                    try
                    {
                        await Task.Delay(interval, ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }

                    if (!ct.IsCancellationRequested && !_disposed && Volatile.Read(ref _settings).AutoScheduleEnabled)
                    {
                        await RunPipelineAsync().ConfigureAwait(false);
                    }
                }
            }, ct);
        }

        public void CancelCurrentRun()
        {
            CancellationTokenSource? ctsToCancel;
            lock (_stateLock)
            {
                ctsToCancel = _currentRunCts;
            }

            if (ctsToCancel == null)
                return;

            try
            {
                ctsToCancel.Cancel();
                Log("Cancellation requested by user.");
            }
            catch { }
        }

        /// <summary>
        /// Cancels any active pipeline run and acquires the exclusive run lock so core binaries
        /// can be safely replaced without file-lock races or scheduler interference.
        /// </summary>
        public async Task<IDisposable?> TryPauseForCoreUpdateAsync(TimeSpan timeout)
        {
            if (_disposed) return null;

            CancelCurrentRun();
            try
            {
                if (await _runLock.WaitAsync(timeout).ConfigureAwait(false))
                {
                    return new RunLockReleaser(_runLock);
                }
            }
            catch (ObjectDisposedException)
            {
            }

            return null;
        }

        private sealed class RunLockReleaser : IDisposable
        {
            private SemaphoreSlim? _lock;
            public RunLockReleaser(SemaphoreSlim runLock) => _lock = runLock;
            public void Dispose()
            {
                var l = Interlocked.Exchange(ref _lock, null);
                if (l == null) return;
                try { l.Release(); } catch (ObjectDisposedException) { }
            }
        }

        private static bool IsUdpOnly(ProxyNode n) =>
            n.Protocol is ProxyProtocol.Hysteria2 or ProxyProtocol.Tuic or ProxyProtocol.WireGuard;

        public async Task RunPipelineAsync()
        {
            if (_disposed) return;

            bool acquired;
            try
            {
                acquired = await _runLock.WaitAsync(0).ConfigureAwait(false);
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            if (!acquired)
            {
                Log("Pipeline is already running.");
                return;
            }

            var runCts = new CancellationTokenSource();
            lock (_stateLock)
            {
                if (_disposed)
                {
                    runCts.Dispose();
                    try { _runLock.Release(); } catch (ObjectDisposedException) { }
                    return;
                }
                _currentRunCts = runCts;
            }

            var ct = runCts.Token;
            var s = Volatile.Read(ref _settings).Clone();
            var subsSnapshot = s.Subscriptions;

            try
            {
                UpdateSnapshot(prev => new PipelineSnapshot
                {
                    IsRunning = true,
                    CurrentStage = "1/7 Fetching Subscriptions",
                    DetailMessage = "Downloading config lists...",
                    ProgressPercent = 2,
                    FinalSurvivingCount = prev.FinalSurvivingCount,
                    LastCompletedUtc = prev.LastCompletedUtc,
                    NextScheduledUtc = prev.NextScheduledUtc
                });

                // 1. Fetch & parse all enabled subscription URLs (compressed, concurrency-limited, with retries)
                var fetched = await FetchAllSubscriptionsAsync(subsSnapshot, s.UseSystemProxyForDownloads, ct).ConfigureAwait(false);
                UpdateSnapshot(prev => prev with { FetchedCount = fetched.Count });
                Log($"Fetched {fetched.Count} configs from {subsSnapshot.Count(x => x.Enabled && !string.IsNullOrWhiteSpace(x.Url))} active URL(s).");

                if (fetched.Count == 0)
                {
                    Log("No configs fetched. Keeping previous subscription payload.");
                    CompleteRun("Idle", "No configs fetched from subscription URLs.");
                    return;
                }

                var current = fetched;

                // 2. Remove Duplicates (Exact V2RayN CompareProfileItem)
                if (s.EnableDeduplication)
                {
                    UpdateStage("2/7 Removing Duplicates", $"Deduplicating {current.Count} configs...", 10);
                    int before = current.Count;
                    current = DeduplicationService.RemoveDuplicates(current, s.KeepOlderDedupl);
                    UpdateSnapshot(prev => prev with { AfterDedupCount = current.Count });
                    Log($"Deduplication complete: {before} -> {current.Count} configs (removed {before - current.Count} duplicates).");
                }
                else
                {
                    UpdateSnapshot(prev => prev with { AfterDedupCount = current.Count });
                    Log("Skipped Deduplication step (disabled in Settings).");
                }

                // Early structural pre-filter so malformed (or disallowed unencrypted) configs never waste Tcping sockets
                int preFilterCount = current.Count;
                int unencryptedSkipped = !s.AllowInsecureAndUnencrypted
                    ? current.Count(CoreConfigGenerator.IsUnencryptedVlessOrTrojan)
                    : 0;
                current = current.Where(n => CoreConfigGenerator.IsStructurallyValid(n, s.AllowInsecureAndUnencrypted)).ToList();
                if (current.Count < preFilterCount)
                {
                    var extra = unencryptedSkipped > 0
                        ? $" (including {unencryptedSkipped} unencrypted VLESS/Trojan — enable 'Allow insecure & unencrypted connections' in Settings to include them)"
                        : string.Empty;
                    Log($"Pre-filter removed {preFilterCount - current.Count} config(s){extra}.");
                }

                if (current.Count == 0)
                {
                    Log("0 structurally valid configs remained. Keeping previous subscription payload.");
                    CompleteRun("Completed", "0 valid configs remained after pre-filtering (kept previous cache).");
                    return;
                }

                // 3. Test Tcping + Remove Invalids (bypass UDP-only protocols: Hysteria2, TUIC, WireGuard)
                if (s.EnableTcpingTest)
                {
                    var tcpCandidates = current.Where(n => !IsUdpOnly(n)).ToList();
                    int udpBypassed = current.Count - tcpCandidates.Count;
                    if (udpBypassed > 0)
                    {
                        Log($"Bypassing Tcping for {udpBypassed} UDP-only config(s) (Hysteria2/TUIC/WireGuard).");
                    }

                    UpdateStage("3/7 Testing Tcping", $"Testing TCP latency on {tcpCandidates.Count} configs...", 15);
                    await _speedtest.RunTcpingAsync(tcpCandidates, s, (done, total) =>
                    {
                        var pct = 15 + (done * 25.0 / Math.Max(1, total));
                        UpdateStage("3/7 Testing Tcping", $"Tcping {done}/{total}...", pct);
                    }, ct).ConfigureAwait(false);

                    int before = current.Count;
                    current = current.Where(n => IsUdpOnly(n) || n.TcpingMs > 0).ToList();
                    UpdateSnapshot(prev => prev with { AfterTcpingCount = current.Count });
                    Log($"Tcping complete: {current.Count} valid ({udpBypassed} UDP bypassed), removed {before - current.Count} invalid.");

                    if (current.Count == 0)
                    {
                        Log("0 configs passed Tcping. Keeping previous subscription payload.");
                        CompleteRun("Completed", "0 configs passed Tcping (kept previous cache).");
                        return;
                    }
                }
                else
                {
                    UpdateSnapshot(prev => prev with { AfterTcpingCount = current.Count });
                    Log("Skipped Tcping step (disabled in Settings).");
                }

                // 4. Test Real Delay + Remove Invalids
                if (s.EnableRealDelayTest)
                {
                    UpdateStage("4/7 Testing Real Delay", $"Testing real delay on {current.Count} configs...", 42);
                    await _speedtest.RunRealPingAsync(current, s, (done, total) =>
                    {
                        var pct = 42 + (done * 25.0 / Math.Max(1, total));
                        UpdateStage("4/7 Testing Real Delay", $"Real Delay {done}/{total}...", pct);
                    }, Log, ct).ConfigureAwait(false);

                    int before = current.Count;
                    current = current.Where(n => n.RealDelayMs > 0).ToList();
                    UpdateSnapshot(prev => prev with { AfterRealDelayCount = current.Count });
                    Log($"Real Delay complete: {current.Count} valid, removed {before - current.Count} invalid.");

                    if (current.Count == 0)
                    {
                        Log("0 configs passed Real Delay. Keeping previous subscription payload.");
                        CompleteRun("Completed", "0 configs passed Real Delay (kept previous cache).");
                        return;
                    }
                }
                else
                {
                    UpdateSnapshot(prev => prev with { AfterRealDelayCount = current.Count });
                    Log("Skipped Real Delay step (disabled in Settings).");
                }

                // 5. Test Latency & Download Speed + Filter
                List<ProxyNode> surviving;
                if (s.EnableSpeedTest)
                {
                    UpdateStage("5/7 Testing Latency & Download Speed", $"Speedtesting {current.Count} configs (concurrency {s.MixedConcurrencyCount})...", 68);
                    await _speedtest.RunMixedSpeedtestAsync(current, s, (done, total, node) =>
                    {
                        var pct = 68 + (done * 28.0 / Math.Max(1, total));
                        UpdateStage(
                            "5/7 Testing Latency & Download Speed",
                            $"Tested {done}/{total} — last: {node.ProtocolLabel} {node.RealDelayDisplay} / {node.SpeedDisplay}",
                            pct);
                    }, Log, ct).ConfigureAwait(false);

                    UpdateStage("6/7 Filtering & Sorting", $"Filtering configs >= {s.MinDownloadSpeedMBps:0.##} MB/s...", 97);
                    int validDelayCount = current.Count(n => n.RealDelayMs > 0);
                    int measuredSpeedCount = current.Count(n => n.DownloadSpeedMBps > 0);
                    double maxSpeed = current.Count > 0 ? current.Max(n => n.DownloadSpeedMBps) : 0;

                    surviving = current
                        .Where(n => n.RealDelayMs > 0 && (s.MinDownloadSpeedMBps <= 0 || n.DownloadSpeedMBps >= s.MinDownloadSpeedMBps))
                        .ToList();

                    Log($"Speedtest complete: {validDelayCount}/{current.Count} passed delay, {measuredSpeedCount} measured >0 MB/s (max {maxSpeed:0.0} MB/s), {surviving.Count} met >= {s.MinDownloadSpeedMBps:0.##} MB/s.");

                    surviving = s.OutputSortMode == SortOrderMode.DelayAscending
                        ? surviving.OrderBy(n => n.RealDelayMs).ThenByDescending(n => n.DownloadSpeedMBps).ToList()
                        : surviving.OrderByDescending(n => n.DownloadSpeedMBps).ThenBy(n => n.RealDelayMs).ToList();
                }
                else
                {
                    Log($"Skipped Latency & Download Speed step (disabled in Settings) — serving {current.Count} remaining configs.");
                    UpdateStage("6/7 Sorting", $"Sorting {current.Count} remaining configs...", 97);
                    surviving = current
                        .OrderBy(n => n.RealDelayMs > 0 ? n.RealDelayMs : int.MaxValue)
                        .ThenBy(n => n.TcpingMs > 0 ? n.TcpingMs : int.MaxValue)
                        .ToList();
                }

                if (s.MaxOutputConfigs > 0 && surviving.Count > s.MaxOutputConfigs)
                {
                    surviving = surviving.Take(s.MaxOutputConfigs).ToList();
                }

                if (surviving.Count == 0)
                {
                    Log("0 configs met the final filter criteria. Keeping previous subscription payload.");
                    CompleteRun("Completed", "0 configs met speed filter (kept previous cache).");
                    return;
                }

                // 7. Publish to Local & LAN Subscription Server
                var lanSuffix = !string.IsNullOrEmpty(_server.LanSubscriptionUrl)
                    ? $" (LAN: {_server.LanSubscriptionUrl})"
                    : string.Empty;
                UpdateStage("7/7 Serving Subscription", $"Publishing {surviving.Count} configs to {_server.SubscriptionUrl}{lanSuffix}...", 99);
                PublishResults(surviving, s);

                Log($"Pipeline finished! Serving {surviving.Count} configs at {_server.SubscriptionUrl}{lanSuffix}");
                CompleteRun("Completed", $"Serving {surviving.Count} fast configs at {_server.SubscriptionUrl}{lanSuffix}");
            }
            catch (OperationCanceledException)
            {
                Log("Pipeline run cancelled.");
                CompleteRun("Cancelled", "Run was cancelled.");
            }
            catch (Exception ex)
            {
                Log($"Pipeline error: {ex.Message}");
                CompleteRun("Error", ex.Message);
            }
            finally
            {
                _runner.CleanupTempDirectory();
                lock (_stateLock)
                {
                    if (ReferenceEquals(_currentRunCts, runCts))
                    {
                        _currentRunCts = null;
                    }
                }
                runCts.Dispose();
                try
                {
                    _runLock.Release();
                }
                catch (ObjectDisposedException)
                {
                    // Orchestrator was disposed during shutdown
                }
            }
        }

        private async Task<List<ProxyNode>> FetchAllSubscriptionsAsync(List<SubscriptionSource> subscriptions, bool useSystemProxy, CancellationToken ct)
        {
            var enabled = subscriptions
                .Where(sub => sub.Enabled && !string.IsNullOrWhiteSpace(sub.Url))
                .ToList();

            if (enabled.Count == 0)
                return new List<ProxyNode>();

            const int MaxConcurrentDownloads = 4;
            const int MaxAttempts = 2;
            var perAttemptTimeout = TimeSpan.FromSeconds(90);

            using var handler = new SocketsHttpHandler
            {
                AutomaticDecompression = DecompressionMethods.All,
                ConnectTimeout = TimeSpan.FromSeconds(15),
                EnableMultipleHttp2Connections = true,
                MaxConnectionsPerServer = 8,
                PooledConnectionLifetime = TimeSpan.FromMinutes(2)
            };
            DownloadProxyHelper.Configure(handler, useSystemProxy);
            Log($"Subscription route: {DownloadProxyHelper.Describe(useSystemProxy, enabled[0].Url.Trim())}.");

            using var http = new HttpClient(handler)
            {
                Timeout = Timeout.InfiniteTimeSpan
            };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("v2rayN/7.0");

            using var downloadGate = new SemaphoreSlim(MaxConcurrentDownloads, MaxConcurrentDownloads);

            var fetchTasks = enabled.Select(async sub =>
            {
                await downloadGate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    var url = sub.Url.Trim();
                    for (int attempt = 1; attempt <= MaxAttempts; attempt++)
                    {
                        try
                        {
                            if (attempt == 1)
                                Log($"Downloading subscription: {sub.Name} ({url})");
                            else
                                Log($"Retrying subscription ({attempt}/{MaxAttempts}): {sub.Name}");

                            using var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                            attemptCts.CancelAfter(perAttemptTimeout);

                            using var response = await http.GetAsync(
                                url,
                                HttpCompletionOption.ResponseHeadersRead,
                                attemptCts.Token).ConfigureAwait(false);
                            response.EnsureSuccessStatusCode();

                            if (response.Content.Headers.ContentLength > MaxSubscriptionBytes)
                            {
                                Log($"Skipped {sub.Name}: response size exceeds {MaxSubscriptionBytes / (1024 * 1024)} MB limit.");
                                return new List<ProxyNode>();
                            }

                            var text = await ReadContentWithLimitAsync(response.Content, MaxSubscriptionBytes, attemptCts.Token).ConfigureAwait(false);
                            var parsed = NodeParser.ParseSubscriptionContent(text, sub.Name);
                            Log($"Parsed {parsed.Count} configs from {sub.Name}.");
                            return parsed;
                        }
                        catch (OperationCanceledException) when (ct.IsCancellationRequested)
                        {
                            throw;
                        }
                        catch (OperationCanceledException)
                        {
                            if (attempt < MaxAttempts)
                            {
                                Log($"Timed out fetching {sub.Name} after {(int)perAttemptTimeout.TotalSeconds}s — retrying...");
                                await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
                                continue;
                            }

                            Log($"Failed to fetch {sub.Name}: Timed out after {(int)perAttemptTimeout.TotalSeconds}s ({MaxAttempts} attempts).");
                            return new List<ProxyNode>();
                        }
                        catch (HttpRequestException ex) when (IsTransientHttpError(ex) && attempt < MaxAttempts)
                        {
                            Log($"Transient error fetching {sub.Name} ({ex.Message}) — retrying...");
                            await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            Log($"Failed to fetch {sub.Name}: {ex.Message}");
                            return new List<ProxyNode>();
                        }
                    }

                    return new List<ProxyNode>();
                }
                finally
                {
                    downloadGate.Release();
                }
            }).ToArray();

            var results = await Task.WhenAll(fetchTasks).ConfigureAwait(false);
            var allNodes = new List<ProxyNode>(results.Sum(r => r.Count));
            foreach (var list in results)
            {
                allNodes.AddRange(list);
            }

            return allNodes;
        }

        private static async Task<string> ReadContentWithLimitAsync(HttpContent content, int maxBytes, CancellationToken ct)
        {
            await using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var ms = new MemoryStream();
            var buffer = new byte[16384];
            int total = 0;

            while (true)
            {
                int read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
                if (read <= 0) break;

                total += read;
                if (total > maxBytes)
                    throw new InvalidOperationException($"Subscription payload exceeded {maxBytes / (1024 * 1024)} MB limit.");

                ms.Write(buffer, 0, read);
            }

            return Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
        }

        private static bool IsTransientHttpError(HttpRequestException ex)
        {
            if (ex.StatusCode is null)
                return true;

            int code = (int)ex.StatusCode.Value;
            return code == 408 || code == 429 || code >= 500;
        }

        private void PublishResults(List<ProxyNode> surviving, AppSettings settings)
        {
            _survivingNodes = surviving;
            UpdateSnapshot(prev => prev with { FinalSurvivingCount = surviving.Count });

            var lines = surviving.Select(n => NodeParser.FormatExportUri(n, settings.AppendMetricsToRemarks));
            var rawPayload = string.Join("\n", lines);
            var base64Payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(rawPayload));

            _server.UpdatePayload(rawPayload, base64Payload, surviving.Count, DateTime.UtcNow);
            _settingsService.SaveLastSubscription(rawPayload, base64Payload);

            OnSurvivingNodesChanged?.Invoke(_survivingNodes);
        }

        private void UpdateStage(string stage, string detail, double percent)
        {
            UpdateSnapshot(prev => prev with
            {
                CurrentStage = stage,
                DetailMessage = detail,
                ProgressPercent = Math.Clamp(percent, 0, 100)
            });
        }

        private void CompleteRun(string stage, string detail)
        {
            UpdateSnapshot(prev => prev with
            {
                IsRunning = false,
                CurrentStage = stage,
                DetailMessage = detail,
                ProgressPercent = stage == "Completed" ? 100 : 0,
                LastCompletedUtc = DateTime.UtcNow
            });
        }

        private void UpdateSnapshot(Func<PipelineSnapshot, PipelineSnapshot> updater)
        {
            PipelineSnapshot next;
            lock (_snapshotLock)
            {
                _snapshot = updater(_snapshot);
                next = _snapshot;
            }
            OnSnapshotChanged?.Invoke(next);
        }

        private void Log(string message) => OnLog?.Invoke($"[{DateTime.Now:HH:mm:ss}] {message}");

        public void Dispose()
        {
            CancellationTokenSource? schedCts;
            CancellationTokenSource? runCts;

            lock (_stateLock)
            {
                if (_disposed) return;
                _disposed = true;
                schedCts = _schedulerCts;
                runCts = _currentRunCts;
                _schedulerCts = null;
            }

            try { schedCts?.Cancel(); } catch { }
            try { runCts?.Cancel(); } catch { }
            try { schedCts?.Dispose(); } catch { }

            // Wait briefly for any active run to exit; only dispose _runLock if we actually acquired it
            bool lockAcquired = false;
            try
            {
                lockAcquired = _runLock.Wait(500);
                if (lockAcquired)
                {
                    _runLock.Release();
                }
            }
            catch { }

            if (lockAcquired)
            {
                _runLock.Dispose();
            }
        }
    }
}
