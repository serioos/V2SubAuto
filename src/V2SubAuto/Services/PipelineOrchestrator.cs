using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using V2SubAuto.Models;

namespace V2SubAuto.Services
{
    public sealed class PipelineOrchestrator : IDisposable
    {
        private readonly SettingsService _settingsService;
        private readonly SpeedtestEngine _speedtest;
        private readonly LocalSubscriptionServer _server;
        private readonly CoreProcessRunner _runner;

        private readonly SemaphoreSlim _runLock = new(1, 1);
        private readonly object _snapshotLock = new();
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
            _settings = settings;
            _settingsService = settingsService;
            _speedtest = speedtest;
            _server = server;
            _runner = runner;
        }

        public void UpdateSettings(AppSettings settings)
        {
            _settings = settings;
            RestartScheduler();
        }

        public void StartScheduler()
        {
            RestartScheduler();
        }

        public void RestartScheduler()
        {
            if (_disposed) return;

            try { _schedulerCts?.Cancel(); } catch { }
            _schedulerCts?.Dispose();
            _schedulerCts = null;

            if (!_settings.AutoScheduleEnabled)
            {
                UpdateSnapshot(s => s with { NextScheduledUtc = null });
                return;
            }

            _schedulerCts = new CancellationTokenSource();
            var ct = _schedulerCts.Token;

            _ = Task.Run(async () =>
            {
                while (!ct.IsCancellationRequested && !_disposed)
                {
                    var interval = TimeSpan.FromMinutes(Math.Max(1, _settings.RefreshIntervalMinutes));
                    UpdateSnapshot(s => s with { NextScheduledUtc = DateTime.UtcNow.Add(interval) });

                    try
                    {
                        await Task.Delay(interval, ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }

                    if (!ct.IsCancellationRequested && !_disposed && _settings.AutoScheduleEnabled)
                    {
                        await RunPipelineAsync().ConfigureAwait(false);
                    }
                }
            }, ct);
        }

        public void CancelCurrentRun()
        {
            try
            {
                _currentRunCts?.Cancel();
                Log("Cancellation requested by user.");
            }
            catch { }
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
            _currentRunCts = runCts;
            var ct = runCts.Token;
            var s = _settings;
            var subsSnapshot = s.Subscriptions.ToList();

            try
            {
                UpdateSnapshot(prev => new PipelineSnapshot
                {
                    IsRunning = true,
                    CurrentStage = "1/7 Fetching Subscriptions",
                    DetailMessage = "Downloading config lists...",
                    ProgressPercent = 2,
                    LastCompletedUtc = prev.LastCompletedUtc,
                    NextScheduledUtc = prev.NextScheduledUtc
                });

                // 1. Fetch & parse all enabled subscription URLs in parallel
                var fetched = await FetchAllSubscriptionsAsync(subsSnapshot, ct).ConfigureAwait(false);
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
                    CompleteRun("Completed", "0 valid configs remained after pre-filtering.");
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

                    UpdateStage("6/7 Filtering & Sorting", $"Filtering configs >= {s.MinDownloadSpeedMBps:0.0} MB/s...", 97);
                    int validDelayCount = current.Count(n => n.RealDelayMs > 0);
                    int measuredSpeedCount = current.Count(n => n.DownloadSpeedMBps > 0);
                    double maxSpeed = current.Count > 0 ? current.Max(n => n.DownloadSpeedMBps) : 0;

                    surviving = current
                        .Where(n => n.RealDelayMs > 0 && n.DownloadSpeedMBps > 0 && n.DownloadSpeedMBps >= s.MinDownloadSpeedMBps)
                        .ToList();

                    Log($"Speedtest complete: {validDelayCount}/{current.Count} passed delay, {measuredSpeedCount} measured >0 MB/s (max {maxSpeed:0.0} MB/s), {surviving.Count} met >= {s.MinDownloadSpeedMBps:0.0} MB/s.");

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
                if (ReferenceEquals(_currentRunCts, runCts))
                {
                    _currentRunCts = null;
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

        private async Task<List<ProxyNode>> FetchAllSubscriptionsAsync(List<SubscriptionSource> subscriptions, CancellationToken ct)
        {
            var enabled = subscriptions
                .Where(sub => sub.Enabled && !string.IsNullOrWhiteSpace(sub.Url))
                .ToList();

            if (enabled.Count == 0)
                return new List<ProxyNode>();

            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("v2rayN/7.0");

            var fetchTasks = enabled.Select(async sub =>
            {
                try
                {
                    Log($"Downloading subscription: {sub.Name} ({sub.Url})");
                    var text = await http.GetStringAsync(sub.Url.Trim(), ct).ConfigureAwait(false);
                    var parsed = NodeParser.ParseSubscriptionContent(text, sub.Name);
                    Log($"Parsed {parsed.Count} configs from {sub.Name}.");
                    return parsed;
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    Log($"Failed to fetch {sub.Name}: {ex.Message}");
                    return new List<ProxyNode>();
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
            if (_disposed) return;
            _disposed = true;

            try { _schedulerCts?.Cancel(); } catch { }
            try { _currentRunCts?.Cancel(); } catch { }
            _schedulerCts?.Dispose();
            _schedulerCts = null;

            // Wait briefly for any active run to exit before disposing the semaphore
            try
            {
                if (_runLock.Wait(500))
                {
                    _runLock.Release();
                }
            }
            catch { }

            _runLock.Dispose();
        }
    }
}
