using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using V2SubAuto.Models;

namespace V2SubAuto.Services
{
    /// <summary>
    /// High-throughput replication of V2RayN's SpeedtestService, ConnectionHandler.GetRealPingTime,
    /// and DownloaderHelper.DownloadDataAsync4Speed with batched cores, DNS/endpoint caching,
    /// keep-alive reuse, smart mirror failover, and 3s zero-byte stall abort.
    /// </summary>
    public sealed partial class SpeedtestEngine
    {
        private const string BrowserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
        private const int MaxGlobalRealPingConcurrency = 250;
        private static readonly TimeSpan ReadStallTimeout = TimeSpan.FromSeconds(3);
        private readonly CoreProcessRunner _runner;
        private readonly SettingsService _settingsService;

        [GeneratedRegex(@"(?:proxy|mixed|relay)(\d+)")]
        private static partial Regex BadNodeTagRegex();

        [GeneratedRegex(@"(outbound|endpoint|inbound)\[(\d+)\]", RegexOptions.IgnoreCase)]
        private static partial Regex BadNodeIndexRegex();

        public SpeedtestEngine(CoreProcessRunner runner, SettingsService settingsService)
        {
            _runner = runner;
            _settingsService = settingsService;
        }

        // =====================================================================
        // Step 2: Test Tcping (with per-run DNS & endpoint cache + IPv4 preference)
        // =====================================================================
        public async Task RunTcpingAsync(
            List<ProxyNode> nodes,
            AppSettings settings,
            Action<int, int> onProgress,
            CancellationToken ct)
        {
            if (nodes.Count == 0) return;

            int completed = 0;
            int batchSize = Math.Max(1, settings.TcpingBatchSize);
            var timeout = TimeSpan.FromSeconds(Math.Max(1, settings.TcpingTimeoutSeconds));
            var delayInterval = TimeSpan.FromSeconds(Math.Max(0, settings.BatchDelayIntervalSeconds));

            // Lazy<Task<T>> ensures only a single probe/DNS lookup executes per unique key on concurrent cache misses
            var dnsCache = new ConcurrentDictionary<string, Lazy<Task<IPAddress[]>>>(StringComparer.OrdinalIgnoreCase);
            var endpointCache = new ConcurrentDictionary<(string Host, int Port), Lazy<Task<int>>>();

            foreach (var batch in Chunk(nodes, batchSize))
            {
                ct.ThrowIfCancellationRequested();

                var parallelOpts = new ParallelOptions
                {
                    MaxDegreeOfParallelism = Math.Min(batch.Count, 500),
                    CancellationToken = ct
                };

                await Parallel.ForEachAsync(batch, parallelOpts, async (node, _) =>
                {
                    var key = (Host: (node.Address ?? string.Empty).Trim().ToLowerInvariant(), node.Port);
                    var lazy = endpointCache.GetOrAdd(
                        key,
                        k => new Lazy<Task<int>>(
                            () => GetTcpingTimeAsync(k.Host, k.Port, timeout, dnsCache, ct),
                            LazyThreadSafetyMode.ExecutionAndPublication));

                    node.TcpingMs = await lazy.Value.ConfigureAwait(false);

                    var done = Interlocked.Increment(ref completed);
                    if (done % 50 == 0 || done == nodes.Count)
                    {
                        onProgress(done, nodes.Count);
                    }
                }).ConfigureAwait(false);

                if (delayInterval > TimeSpan.Zero && completed < nodes.Count)
                {
                    await Task.Delay(delayInterval, ct).ConfigureAwait(false);
                }
            }
        }

        private static async Task<int> GetTcpingTimeAsync(
            string host,
            int port,
            TimeSpan timeout,
            ConcurrentDictionary<string, Lazy<Task<IPAddress[]>>> dnsCache,
            CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(host) || port <= 0)
                return -1;

            try
            {
                using var timeoutCts = new CancellationTokenSource(timeout);
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
                var token = linkedCts.Token;

                IPAddress[] candidates;
                if (IPAddress.TryParse(host, out var parsedIp))
                {
                    candidates = new[] { parsedIp };
                }
                else
                {
                    var dnsLazy = dnsCache.GetOrAdd(
                        host,
                        h => new Lazy<Task<IPAddress[]>>(
                            () => ResolveHostAddressesAsync(h, timeout, ct),
                            LazyThreadSafetyMode.ExecutionAndPublication));

                    candidates = await dnsLazy.Value.ConfigureAwait(false);
                    if (candidates.Length == 0)
                    {
                        // Evict transient empty DNS results so later nodes on the same domain can retry
                        if (!ct.IsCancellationRequested)
                        {
                            dnsCache.TryRemove(new KeyValuePair<string, Lazy<Task<IPAddress[]>>>(host, dnsLazy));
                        }
                        return -1;
                    }
                }

                // Prefer IPv4 first; fall back to IPv6 only if no IPv4 exists or IPv4 fails
                var ipv4 = candidates.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                var ipv6 = candidates.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetworkV6);

                if (ipv4 != null)
                {
                    var ms = await TryTcpConnectAsync(ipv4, port, token).ConfigureAwait(false);
                    if (ms > 0) return ms;
                }

                if (ipv6 != null && !token.IsCancellationRequested)
                {
                    var ms = await TryTcpConnectAsync(ipv6, port, token).ConfigureAwait(false);
                    if (ms > 0) return ms;
                }

                return -1;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                return -1;
            }
        }

        private static async Task<IPAddress[]> ResolveHostAddressesAsync(string host, TimeSpan timeout, CancellationToken ct)
        {
            try
            {
                using var timeoutCts = new CancellationTokenSource(timeout);
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
                return await Dns.GetHostAddressesAsync(host, linkedCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                return Array.Empty<IPAddress>();
            }
        }

        private static async Task<int> TryTcpConnectAsync(IPAddress ipAddress, int port, CancellationToken token)
        {
            try
            {
                var endPoint = new IPEndPoint(ipAddress, port);
                using var socket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                var sw = Stopwatch.StartNew();
                await socket.ConnectAsync(endPoint, token).ConfigureAwait(false);
                sw.Stop();
                return Math.Max(1, (int)sw.ElapsedMilliseconds);
            }
            catch
            {
                return -1;
            }
        }

        // =====================================================================
        // Step 3: Test Real Delay (batched Xray & sing-box cores in parallel)
        // =====================================================================
        public async Task RunRealPingAsync(
            List<ProxyNode> nodes,
            AppSettings settings,
            Action<int, int> onProgress,
            Action<string> log,
            CancellationToken ct)
        {
            if (nodes.Count == 0) return;

            int completed = 0;
            int total = nodes.Count;
            int pageSize = Math.Clamp(settings.RealPingBatchSize, 1, AppSettings.MaxRealPingBatchSize);

            void MarkOneCompleted()
            {
                var d = Interlocked.Increment(ref completed);
                if (d % 20 == 0 || d == total) onProgress(d, total);
            }

            bool allowInsecure = settings.AllowInsecureAndUnencrypted;
            var xrayNodes = nodes.Where(n => CoreConfigGenerator.ResolveCoreEngine(n, allowInsecure) == CoreEngineType.Xray).ToList();
            var singboxNodes = nodes.Where(n => CoreConfigGenerator.ResolveCoreEngine(n, allowInsecure) == CoreEngineType.SingBox).ToList();

            using var globalProbeGate = new SemaphoreSlim(MaxGlobalRealPingConcurrency, MaxGlobalRealPingConcurrency);
            var tasks = new List<Task>(2);

            if (xrayNodes.Count > 0)
            {
                tasks.Add(RunRealPingCoreGroupAsync(
                    CoreEngineType.Xray,
                    _settingsService.ResolvePath(settings.XrayExecutablePath),
                    xrayNodes,
                    pageSize,
                    settings,
                    globalProbeGate,
                    MarkOneCompleted,
                    log,
                    ct));
            }

            if (singboxNodes.Count > 0)
            {
                tasks.Add(RunRealPingCoreGroupAsync(
                    CoreEngineType.SingBox,
                    _settingsService.ResolvePath(settings.SingboxExecutablePath),
                    singboxNodes,
                    pageSize,
                    settings,
                    globalProbeGate,
                    MarkOneCompleted,
                    log,
                    ct));
            }

            await Task.WhenAll(tasks).ConfigureAwait(false);
            onProgress(total, total);
        }

        private async Task RunRealPingCoreGroupAsync(
            CoreEngineType coreType,
            string exePath,
            List<ProxyNode> groupNodes,
            int pageSize,
            AppSettings settings,
            SemaphoreSlim globalProbeGate,
            Action markOneCompleted,
            Action<string> log,
            CancellationToken ct)
        {
            if (!File.Exists(exePath))
            {
                log($"Warning: {coreType} executable not found at {exePath}. Skipping {groupNodes.Count} {coreType} configs.");
                foreach (var n in groupNodes)
                {
                    n.RealDelayMs = -1;
                    markOneCompleted();
                }
                return;
            }

            var failedBatches = new List<ProxyNode>();
            var delayInterval = TimeSpan.FromSeconds(Math.Max(0, settings.BatchDelayIntervalSeconds));
            var pingTimeout = TimeSpan.FromSeconds(Math.Max(2, settings.RealPingTimeoutSeconds));

            int effectiveBatchSize = Math.Clamp(pageSize, 1, AppSettings.MaxRealPingBatchSize);
            var batches = Chunk(groupNodes, effectiveBatchSize).ToList();
            var batchLock = new object();

            var outerOpts = new ParallelOptions
            {
                MaxDegreeOfParallelism = batches.Count > 1 && effectiveBatchSize >= 50 ? Math.Min(3, batches.Count) : 1,
                CancellationToken = ct
            };

            await Parallel.ForEachAsync(batches, outerOpts, async (batch, outerCt) =>
            {
                var (proc, testable, err) = await StartBatchWithEjectionAsync(
                    coreType,
                    exePath,
                    batch,
                    settings.AllowInsecureAndUnencrypted,
                    dropped =>
                    {
                        dropped.RealDelayMs = -1;
                        markOneCompleted();
                    },
                    outerCt).ConfigureAwait(false);

                if (proc == null)
                {
                    if (testable.Count > 0)
                    {
                        if (!string.IsNullOrWhiteSpace(err))
                        {
                            var firstLine = err.Split('\n')[0].Trim();
                            log($"{coreType} batch ({testable.Count} nodes) failed to start: {firstLine}");
                        }

                        if (testable.Count == 1)
                        {
                            testable[0].RealDelayMs = -1;
                            markOneCompleted();
                        }
                        else
                        {
                            lock (batchLock)
                            {
                                failedBatches.AddRange(testable);
                            }
                        }
                    }
                    return;
                }

                using (proc)
                {
                    var parallelOpts = new ParallelOptions
                    {
                        MaxDegreeOfParallelism = Math.Min(testable.Count, MaxGlobalRealPingConcurrency),
                        CancellationToken = outerCt
                    };

                    await Parallel.ForEachAsync(testable, parallelOpts, async (node, innerCt) =>
                    {
                        await globalProbeGate.WaitAsync(innerCt).ConfigureAwait(false);
                        try
                        {
                            node.RealDelayMs = await GetRealPingTimeAsync(
                                node.LocalTestPort,
                                settings.RealPingTestUrl,
                                pingTimeout,
                                innerCt).ConfigureAwait(false);
                        }
                        finally
                        {
                            globalProbeGate.Release();
                        }
                        markOneCompleted();
                    }).ConfigureAwait(false);
                }

                if (delayInterval > TimeSpan.Zero)
                {
                    await Task.Delay(delayInterval, outerCt).ConfigureAwait(false);
                }
            }).ConfigureAwait(false);

            // V2RayN batch-halving retry when a multi-inbound core fails to start
            if (failedBatches.Count > 0)
            {
                var nextSize = Math.Min(effectiveBatchSize, failedBatches.Count) / 2;
                if (nextSize >= 1)
                {
                    log($"Retesting {failedBatches.Count} {coreType} configs in smaller batches of {nextSize}...");
                    await RunRealPingCoreGroupAsync(coreType, exePath, failedBatches, nextSize, settings, globalProbeGate, markOneCompleted, log, ct).ConfigureAwait(false);
                }
                else
                {
                    foreach (var n in failedBatches)
                    {
                        n.RealDelayMs = -1;
                        markOneCompleted();
                    }
                }
            }
        }

        // =====================================================================
        // Step 4: Batched Speedtest (concurrent Xray & sing-box engines sharing
        // a global concurrency semaphore, reusing Real Delay & HttpClient per port)
        // =====================================================================
        public async Task RunMixedSpeedtestAsync(
            List<ProxyNode> nodes,
            AppSettings settings,
            Action<int, int, ProxyNode> onNodeTested,
            Action<string> log,
            CancellationToken ct)
        {
            if (nodes.Count == 0) return;

            // Test lowest-latency nodes first so the best candidates appear immediately
            var ordered = nodes
                .OrderBy(n => n.RealDelayMs > 0 ? n.RealDelayMs : int.MaxValue)
                .ThenBy(n => n.TcpingMs > 0 ? n.TcpingMs : int.MaxValue)
                .ToList();

            int completed = 0;
            int fastFound = 0;
            int loggedError = 0;
            void LogFirstSpeedError(string msg)
            {
                if (Interlocked.Exchange(ref loggedError, 1) == 0)
                    log(msg);
            }

            bool allowEarlyStop = settings.MaxOutputConfigs > 0 && settings.OutputSortMode == SortOrderMode.DelayAscending;
            using var earlyStopCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var activeCt = earlyStopCts.Token;

            var xrayPath = _settingsService.ResolvePath(settings.XrayExecutablePath);
            var singboxPath = _settingsService.ResolvePath(settings.SingboxExecutablePath);
            var pingTimeout = TimeSpan.FromSeconds(Math.Max(2, settings.RealPingTimeoutSeconds));
            var speedTimeout = TimeSpan.FromSeconds(Math.Max(2, settings.SpeedTestTimeoutSeconds));
            int concurrency = Math.Max(1, settings.MixedConcurrencyCount);
            bool allowInsecure = settings.AllowInsecureAndUnencrypted;

            var xrayNodes = ordered.Where(n => CoreConfigGenerator.ResolveCoreEngine(n, allowInsecure) == CoreEngineType.Xray).ToList();
            var singboxNodes = ordered.Where(n => CoreConfigGenerator.ResolveCoreEngine(n, allowInsecure) == CoreEngineType.SingBox).ToList();

            using var sharedConcurrencyGate = new SemaphoreSlim(concurrency, concurrency);
            var mirrorFailures = new ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            async Task RunEngineSpeedtestAsync(CoreEngineType coreType, string exePath, List<ProxyNode> groupNodes, int maxBatchSize)
            {
                if (groupNodes.Count == 0) return;

                if (!File.Exists(exePath))
                {
                    log($"Warning: {coreType} executable not found at {exePath}. Skipping {groupNodes.Count} {coreType} configs.");
                    foreach (var n in groupNodes)
                    {
                        n.DownloadSpeedMBps = 0;
                        var done = Interlocked.Increment(ref completed);
                        onNodeTested(done, ordered.Count, n);
                    }
                    return;
                }

                var failedBatches = new List<ProxyNode>();

                foreach (var batch in Chunk(groupNodes, Math.Max(1, maxBatchSize)))
                {
                    if (activeCt.IsCancellationRequested) break;

                    var (proc, testable, err) = await StartBatchWithEjectionAsync(
                        coreType,
                        exePath,
                        batch,
                        allowInsecure,
                        dropped =>
                        {
                            dropped.RealDelayMs = -1;
                            dropped.DownloadSpeedMBps = 0;
                            var done = Interlocked.Increment(ref completed);
                            onNodeTested(done, ordered.Count, dropped);
                        },
                        activeCt).ConfigureAwait(false);

                    if (proc == null)
                    {
                        if (testable.Count > 0)
                        {
                            if (!string.IsNullOrWhiteSpace(err))
                            {
                                var firstLine = err.Split('\n')[0].Trim();
                                log($"{coreType} speedtest batch ({testable.Count} nodes) failed to start: {firstLine}");
                            }

                            if (testable.Count == 1)
                            {
                                testable[0].RealDelayMs = -1;
                                testable[0].DownloadSpeedMBps = 0;
                                var done = Interlocked.Increment(ref completed);
                                onNodeTested(done, ordered.Count, testable[0]);
                            }
                            else
                            {
                                failedBatches.AddRange(testable);
                            }
                        }
                        continue;
                    }

                    using (proc)
                    {
                        var parallelOpts = new ParallelOptions
                        {
                            MaxDegreeOfParallelism = concurrency,
                            CancellationToken = activeCt
                        };

                        try
                        {
                            await Parallel.ForEachAsync(testable, parallelOpts, async (node, innerCt) =>
                            {
                                await sharedConcurrencyGate.WaitAsync(innerCt).ConfigureAwait(false);
                                try
                                {
                                    // Reuse a single HttpClient/handler per node port across Real Delay (if needed) and Speedtest
                                    using var handler = CreateProxyHandler(node.LocalTestPort, TimeSpan.FromSeconds(Math.Max(4, pingTimeout.TotalSeconds)));
                                    using var client = CreateProxyClient(handler);

                                    // Skip duplicate Real Delay ping if Step 3 already measured a valid delay
                                    int delay = settings.EnableRealDelayTest && node.RealDelayMs > 0
                                        ? node.RealDelayMs
                                        : await GetRealPingTimeWithClientAsync(client, settings.RealPingTestUrl, pingTimeout, innerCt).ConfigureAwait(false);

                                    node.RealDelayMs = delay;

                                    if (delay > 0)
                                    {
                                        node.DownloadSpeedMBps = await MeasureDownloadSpeedMBpsAsync(
                                            client,
                                            settings.SpeedTestUrl,
                                            speedTimeout,
                                            mirrorFailures,
                                            LogFirstSpeedError,
                                            innerCt).ConfigureAwait(false);
                                    }
                                    else
                                    {
                                        node.DownloadSpeedMBps = 0;
                                    }

                                    var done = Interlocked.Increment(ref completed);
                                    onNodeTested(done, ordered.Count, node);

                                    if (allowEarlyStop &&
                                        node.RealDelayMs > 0 &&
                                        (settings.MinDownloadSpeedMBps <= 0 || node.DownloadSpeedMBps >= settings.MinDownloadSpeedMBps))
                                    {
                                        if (Interlocked.Increment(ref fastFound) >= settings.MaxOutputConfigs)
                                        {
                                            log($"Early stop: reached {settings.MaxOutputConfigs} qualifying fast configs.");
                                            try { earlyStopCts.Cancel(); } catch { }
                                        }
                                    }
                                }
                                finally
                                {
                                    sharedConcurrencyGate.Release();
                                }
                            }).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) when (!ct.IsCancellationRequested && earlyStopCts.IsCancellationRequested)
                        {
                            // Expected early stop once MaxOutputConfigs fast configs are found
                            break;
                        }
                    }
                }

                if (failedBatches.Count > 0 && !activeCt.IsCancellationRequested)
                {
                    int nextSize = Math.Min(maxBatchSize, failedBatches.Count) / 2;
                    if (nextSize >= 1)
                    {
                        log($"Retesting {failedBatches.Count} {coreType} speedtest configs in smaller batches of {nextSize}...");
                        await RunEngineSpeedtestAsync(coreType, exePath, failedBatches, nextSize).ConfigureAwait(false);
                    }
                    else
                    {
                        foreach (var n in failedBatches)
                        {
                            n.RealDelayMs = -1;
                            n.DownloadSpeedMBps = 0;
                            var done = Interlocked.Increment(ref completed);
                            onNodeTested(done, ordered.Count, n);
                        }
                    }
                }
            }

            // Launch Xray and sing-box speedtest engines concurrently so fast sing-box nodes aren't starved
            int initialBatchSize = Math.Clamp(settings.RealPingBatchSize, 1, AppSettings.MaxRealPingBatchSize);
            var engineTasks = new List<Task>(2);
            if (xrayNodes.Count > 0)
                engineTasks.Add(RunEngineSpeedtestAsync(CoreEngineType.Xray, xrayPath, xrayNodes, initialBatchSize));
            if (singboxNodes.Count > 0)
                engineTasks.Add(RunEngineSpeedtestAsync(CoreEngineType.SingBox, singboxPath, singboxNodes, initialBatchSize));

            try
            {
                await Task.WhenAll(engineTasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested && earlyStopCts.IsCancellationRequested)
            {
                // Clean early stop
            }
        }

        private async Task<(CoreProcessInstance? Process, List<ProxyNode> TestableNodes, string? ErrorMessage)> StartBatchWithEjectionAsync(
            CoreEngineType coreType,
            string exePath,
            List<ProxyNode> batch,
            bool allowInsecureAndUnencrypted,
            Action<ProxyNode> onNodeDropped,
            CancellationToken ct)
        {
            var json = coreType == CoreEngineType.Xray
                ? CoreConfigGenerator.GenerateXraySpeedtestConfig(batch, allowInsecureAndUnencrypted, out var testable, out var initialLeasedPorts, out var portAllocFailed)
                : CoreConfigGenerator.GenerateSingboxSpeedtestConfig(batch, allowInsecureAndUnencrypted, out testable, out initialLeasedPorts, out portAllocFailed);

            if (string.IsNullOrEmpty(json) || testable.Count == 0)
            {
                PortAllocator.ReleasePorts(initialLeasedPorts);
                if (portAllocFailed)
                {
                    // Port exhaustion is transient — return batch intact so caller can retry in smaller chunks
                    return (null, new List<ProxyNode>(batch), "Port allocation failed; retrying in smaller batches.");
                }
                foreach (var n in batch) onNodeDropped(n);
                return (null, new List<ProxyNode>(), null);
            }

            var testableSet = new HashSet<string>(testable.Select(t => t.Id));
            foreach (var n in batch)
            {
                if (!testableSet.Contains(n.Id))
                {
                    onNodeDropped(n);
                }
            }

            // Surgical bad-node ejection: if Xray/sing-box names the exact offending "proxy<port>", "mixed<port>", or "relay<port>",
            // drop that single node and immediately retry the remaining batch instead of halving!
            CoreProcessInstance? proc = null;
            string? err = null;
            var activeBatch = testable;
            var currentLeasedPorts = initialLeasedPorts;
            int ejectAttempts = 0;

            while (activeBatch.Count > 0 && ejectAttempts < 25)
            {
                string? currentJson;
                if (ejectAttempts == 0)
                {
                    currentJson = json;
                }
                else
                {
                    currentJson = coreType == CoreEngineType.Xray
                        ? CoreConfigGenerator.GenerateXraySpeedtestConfig(activeBatch, allowInsecureAndUnencrypted, out var retryBatch, out var retryPorts, out var retryPortFailed)
                        : CoreConfigGenerator.GenerateSingboxSpeedtestConfig(activeBatch, allowInsecureAndUnencrypted, out retryBatch, out retryPorts, out retryPortFailed);

                    if (string.IsNullOrEmpty(currentJson) || retryBatch.Count == 0)
                    {
                        PortAllocator.ReleasePorts(retryPorts);
                        if (retryPortFailed)
                        {
                            err = "Port allocation failed during retry; falling back to smaller batches.";
                        }
                        // Preserve activeBatch so caller retries remaining nodes instead of silently dropping them
                        break;
                    }

                    activeBatch = retryBatch;
                    currentLeasedPorts = retryPorts;
                }

                var firstProbePort = activeBatch[0].LocalTestPort;
                var lastProbePort = activeBatch[^1].LocalTestPort;
                (proc, err) = await _runner.StartCoreAsync(
                    coreType,
                    exePath,
                    currentJson,
                    lastProbePort,
                    ct,
                    currentLeasedPorts,
                    activeBatch.Count,
                    firstProbePort).ConfigureAwait(false);

                if (proc != null)
                    break;

                var tagMatch = !string.IsNullOrEmpty(err)
                    ? BadNodeTagRegex().Match(err)
                    : Match.Empty;

                ProxyNode? badNode = null;
                if (tagMatch.Success && int.TryParse(tagMatch.Groups[1].Value, out var badPort))
                {
                    badNode = activeBatch.FirstOrDefault(n => n.LocalTestPort == badPort);
                }
                else if (coreType == CoreEngineType.SingBox && !string.IsNullOrEmpty(err))
                {
                    var idxMatch = BadNodeIndexRegex().Match(err);
                    if (idxMatch.Success && int.TryParse(idxMatch.Groups[2].Value, out var badIdx) && badIdx >= 0)
                    {
                        var kind = idxMatch.Groups[1].Value;
                        if (kind.Equals("outbound", StringComparison.OrdinalIgnoreCase))
                        {
                            var nonWg = activeBatch.Where(n => n.Protocol != ProxyProtocol.WireGuard).ToList();
                            if (badIdx < nonWg.Count) badNode = nonWg[badIdx];
                        }
                        else if (kind.Equals("endpoint", StringComparison.OrdinalIgnoreCase))
                        {
                            var wg = activeBatch.Where(n => n.Protocol == ProxyProtocol.WireGuard).ToList();
                            if (badIdx < wg.Count) badNode = wg[badIdx];
                        }
                        else if (kind.Equals("inbound", StringComparison.OrdinalIgnoreCase) && badIdx < activeBatch.Count)
                        {
                            badNode = activeBatch[badIdx];
                        }
                    }
                }

                if (badNode != null)
                {
                    onNodeDropped(badNode);
                    activeBatch = activeBatch.Where(n => n.Id != badNode.Id).ToList();
                    ejectAttempts++;
                    continue;
                }

                break;
            }

            return (proc, activeBatch, err);
        }

        /// <summary>
        /// 2x HTTP GET to RealPingTestUrl via local proxy with HTTP 2xx/204 validation,
        /// per-probe timeout (preserves probe #1 if probe #2 times out), and keep-alive TLS reuse.
        /// </summary>
        private static async Task<int> GetRealPingTimeAsync(int localPort, string testUrl, TimeSpan timeout, CancellationToken ct)
        {
            using var handler = CreateProxyHandler(localPort, timeout);
            using var client = CreateProxyClient(handler);
            return await GetRealPingTimeWithClientAsync(client, testUrl, timeout, ct).ConfigureAwait(false);
        }

        private static async Task<int> GetRealPingTimeWithClientAsync(HttpClient client, string testUrl, TimeSpan timeout, CancellationToken ct)
        {
            try
            {
                var timings = new List<int>(2);
                for (int i = 0; i < 2; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var probeTimeoutCts = new CancellationTokenSource(timeout);
                        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, probeTimeoutCts.Token);

                        var sw = Stopwatch.StartNew();
                        using var resp = await client.GetAsync(testUrl, HttpCompletionOption.ResponseHeadersRead, linkedCts.Token).ConfigureAwait(false);
                        sw.Stop();

                        if (resp.StatusCode == HttpStatusCode.NoContent || resp.IsSuccessStatusCode)
                        {
                            var ms = Math.Max(1, (int)sw.Elapsed.TotalMilliseconds);
                            timings.Add(ms);
                        }
                        else if (i == 0)
                        {
                            // Captive portal / HTTP 403/502/503 error — reject immediately
                            return -1;
                        }
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch
                    {
                        // If probe #1 already succeeded, keep its timing instead of discarding it
                        if (timings.Count > 0) break;
                        return -1;
                    }
                }

                return timings.Count > 0 ? timings.Min() : -1;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                return -1;
            }
        }

        private static readonly string[] FallbackSpeedMirrors =
        {
            "https://speed.cloudflare.com/__down?bytes=25000000",
            "https://cachefly.cachefly.net/10mb.test",
            "https://ash-speed.hetzner.com/100MB.bin",
            "https://proof.ovh.net/files/10Mb.dat"
        };

        /// <summary>
        /// Streams SpeedTestUrl through local proxy up to SpeedTestTimeout with 3s zero-byte stall abort.
        /// Stops immediately once connected to a mirror (even if slow), failing over through up to 4 mirrors if unreachable.
        /// </summary>
        private static async Task<double> MeasureDownloadSpeedMBpsAsync(
            HttpClient client,
            string primarySpeedTestUrl,
            TimeSpan timeout,
            ConcurrentDictionary<string, int> mirrorFailures,
            Action<string>? onFirstError,
            CancellationToken ct)
        {
            const int MirrorFailureDeprioritizeThreshold = 6;

            var urlsToTry = new List<string>(4);
            if (!string.IsNullOrWhiteSpace(primarySpeedTestUrl))
                urlsToTry.Add(primarySpeedTestUrl.Trim());

            foreach (var mirror in FallbackSpeedMirrors)
            {
                if (urlsToTry.Count >= 4) break;
                if (!urlsToTry.Any(u => string.Equals(u, mirror, StringComparison.OrdinalIgnoreCase)))
                    urlsToTry.Add(mirror);
            }

            // Move mirrors that have repeatedly failed (e.g. broken SSL cert or blocked CDN) to the end
            var orderedUrls = urlsToTry
                .OrderBy(u => mirrorFailures.TryGetValue(u, out var f) && f >= MirrorFailureDeprioritizeThreshold ? 1 : 0)
                .ToList();

            string? lastError = null;
            foreach (var speedTestUrl in orderedUrls)
            {
                ct.ThrowIfCancellationRequested();
                var (connected, speedMBps, error) = await TrySingleMirrorSpeedAsync(client, speedTestUrl, timeout, ct).ConfigureAwait(false);
                if (connected)
                {
                    mirrorFailures[speedTestUrl] = 0;
                    return speedMBps;
                }

                if (!string.IsNullOrEmpty(error))
                {
                    lastError = error;
                    mirrorFailures.AddOrUpdate(speedTestUrl, 1, (_, prev) => prev + 1);
                }
            }

            // Only log once if ALL mirrors failed for a node (avoids noise when mirror #1 fails over cleanly)
            if (!string.IsNullOrEmpty(lastError))
            {
                onFirstError?.Invoke(lastError);
            }

            return 0;
        }

        private static async Task<(bool Connected, double SpeedMBps, string? Error)> TrySingleMirrorSpeedAsync(
            HttpClient client,
            string speedTestUrl,
            TimeSpan timeout,
            CancellationToken ct)
        {
            double maxBytesPerSecond = 0;
            long totalBytes = 0;
            bool connected = false;
            string? error = null;
            Stopwatch? totalSw = null;
            byte[]? buffer = null;

            try
            {
                // Quick 4s header check so blocked mirrors fail over fast
                using var headerTimeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(4));
                using var headerLinkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, headerTimeoutCts.Token);

                using var resp = await client.GetAsync(speedTestUrl, HttpCompletionOption.ResponseHeadersRead, headerLinkedCts.Token).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode)
                {
                    return (false, 0, $"Speedtest HTTP {(int)resp.StatusCode} ({resp.ReasonPhrase}) from {speedTestUrl}");
                }

                connected = true;
                totalSw = Stopwatch.StartNew();

                using var streamTimeoutCts = new CancellationTokenSource(timeout);
                using var streamLinkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, streamTimeoutCts.Token);
                var streamToken = streamLinkedCts.Token;

                await using var stream = await resp.Content.ReadAsStreamAsync(streamToken).ConfigureAwait(false);
                buffer = ArrayPool<byte>.Shared.Rent(65536);

                var windowSw = Stopwatch.StartNew();
                long windowBytes = 0;

                // Single reusable CTS for 3s zero-byte stall abort (avoids per-64KB CTS allocation churn)
                using var stallCts = CancellationTokenSource.CreateLinkedTokenSource(streamToken);

                while (true)
                {
                    stallCts.CancelAfter(ReadStallTimeout);
                    int read = await stream.ReadAsync(buffer.AsMemory(0, 65536), stallCts.Token).ConfigureAwait(false);
                    if (read <= 0) break;

                    totalBytes += read;
                    windowBytes += read;

                    if (windowSw.ElapsedMilliseconds >= 1000)
                    {
                        var bps = windowBytes / windowSw.Elapsed.TotalSeconds;
                        if (bps > maxBytesPerSecond) maxBytesPerSecond = bps;
                        windowBytes = 0;
                        windowSw.Restart();
                    }
                }

                if (windowBytes > 0 && windowSw.Elapsed.TotalSeconds > 0.1)
                {
                    var bps = windowBytes / windowSw.Elapsed.TotalSeconds;
                    if (bps > maxBytesPerSecond) maxBytesPerSecond = bps;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                if (!connected)
                {
                    error = $"Speedtest header timeout from {speedTestUrl}";
                }
                // Timeout or 3s stall abort reached after partial download — normal for speedtest
            }
            catch (Exception ex)
            {
                var detail = ex.InnerException != null ? $"{ex.Message} ({ex.InnerException.Message})" : ex.Message;
                error = $"Speedtest mirror error ({speedTestUrl}): {detail}";
            }
            finally
            {
                totalSw?.Stop();
                if (buffer != null)
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }

            if (maxBytesPerSecond <= 0 && totalBytes > 0 && totalSw != null && totalSw.Elapsed.TotalSeconds > 0.05)
            {
                maxBytesPerSecond = totalBytes / totalSw.Elapsed.TotalSeconds;
            }

            return (connected, Math.Round(maxBytesPerSecond / 1_000_000.0, 1), error);
        }

        private static SocketsHttpHandler CreateProxyHandler(int localPort, TimeSpan connectTimeout)
        {
            return new SocketsHttpHandler
            {
                Proxy = new WebProxy($"http://127.0.0.1:{localPort}"),
                UseProxy = true,
                ConnectTimeout = connectTimeout,
                MaxConnectionsPerServer = 2,
                PooledConnectionLifetime = TimeSpan.FromSeconds(30),
                AllowAutoRedirect = true
            };
        }

        private static HttpClient CreateProxyClient(SocketsHttpHandler handler)
        {
            var client = new HttpClient(handler, disposeHandler: false)
            {
                Timeout = Timeout.InfiniteTimeSpan
            };
            client.DefaultRequestHeaders.UserAgent.ParseAdd(BrowserUserAgent);
            return client;
        }

        private static IEnumerable<List<T>> Chunk<T>(List<T> source, int size)
        {
            for (int i = 0; i < source.Count; i += size)
            {
                yield return source.GetRange(i, Math.Min(size, source.Count - i));
            }
        }
    }
}
