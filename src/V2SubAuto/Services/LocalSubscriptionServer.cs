using System;
using System.Buffers;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace V2SubAuto.Services
{
    /// <summary>
    /// Lightweight local & LAN HTTP/1.1 server built on TcpListener (no Windows UAC/URLACL needed)
    /// serving surviving configs for V2RayN and other LAN devices.
    /// Endpoints:
    ///   GET /sub    -> Base64-encoded share URI list (standard V2RayN subscription format)
    ///   GET /raw    -> Plain-text newline-separated share URI list
    ///   GET /status -> JSON metadata (count, lastUpdatedUtc, subscriptionUrl, lanSubscriptionUrl)
    /// </summary>
    public sealed class LocalSubscriptionServer : IDisposable
    {
        private const int MaxHeaderBytes = 16384;

        private static readonly string[] VirtualAdapterKeywords =
        {
            "vethernet", "hyper-v", "virtualbox", "vmware", "wsl", "docker",
            "tailscale", "wireguard", "wintun", "sing-tun", "tap-windows",
            "loopback", "bluetooth", "zerotier", "hamachi", "radmin", "nordlynx", "proton"
        };

        private TcpListener? _listener;
        private CancellationTokenSource? _cts;
        private Task? _loopTask;

        private readonly object _lock = new();
        private string _base64Payload = string.Empty;
        private string _rawPayload = string.Empty;
        private int _configCount;
        private DateTime? _lastUpdatedUtc;
        private volatile bool _isRunning;

        public int Port { get; private set; }
        public bool AllowLanAccess { get; private set; }
        public bool IsRunning => _isRunning;
        public string? LanIpAddress { get; private set; }

        public string SubscriptionUrl => $"http://127.0.0.1:{Port}/sub";
        public string RawUrl => $"http://127.0.0.1:{Port}/raw";
        public string? LanSubscriptionUrl => AllowLanAccess && !string.IsNullOrEmpty(LanIpAddress)
            ? $"http://{LanIpAddress}:{Port}/sub"
            : null;
        public string? LanRawUrl => AllowLanAccess && !string.IsNullOrEmpty(LanIpAddress)
            ? $"http://{LanIpAddress}:{Port}/raw"
            : null;

        public event Action<string>? OnLog;

        public void UpdatePayload(string rawContent, string base64Content, int count, DateTime updatedUtc)
        {
            lock (_lock)
            {
                _rawPayload = rawContent;
                _base64Payload = base64Content;
                _configCount = count;
                _lastUpdatedUtc = updatedUtc;
            }
        }

        public bool Start(int port, bool allowLan = true)
        {
            Stop();
            Port = port;
            AllowLanAccess = allowLan;
            LanIpAddress = allowLan ? DetectPreferredLanIpv4() : null;

            try
            {
                var bindAddress = allowLan ? IPAddress.Any : IPAddress.Loopback;
                var listener = new TcpListener(bindAddress, port);
                listener.Start();

                var cts = new CancellationTokenSource();
                _listener = listener;
                _cts = cts;
                _isRunning = true;
                _loopTask = Task.Run(() => ListenLoopAsync(listener, cts.Token));

                if (allowLan)
                {
                    var lanText = !string.IsNullOrEmpty(LanSubscriptionUrl)
                        ? $" and LAN at {LanSubscriptionUrl}"
                        : " (bound to 0.0.0.0 for LAN access)";
                    OnLog?.Invoke($"Subscription server listening locally at {SubscriptionUrl}{lanText}");
                }
                else
                {
                    OnLog?.Invoke($"Local subscription server listening at {SubscriptionUrl} (localhost only)");
                }

                return true;
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"Failed to start subscription server on port {port}: {ex.Message}");
                Stop();
                return false;
            }
        }

        public void Stop()
        {
            _isRunning = false;
            var cts = _cts;
            var listener = _listener;
            _cts = null;
            _listener = null;

            try { cts?.Cancel(); } catch { }
            try { listener?.Stop(); } catch { }
            cts?.Dispose();
        }

        private async Task ListenLoopAsync(TcpListener listener, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                }
                catch
                {
                    break;
                }

                // Always start with CancellationToken.None so HandleClientAsync always disposes client
                _ = Task.Run(() => HandleClientAsync(client, ct), CancellationToken.None);
            }
        }

        private async Task HandleClientAsync(TcpClient client, CancellationToken serverCt)
        {
            using (client)
            {
                try
                {
                    await using var stream = client.GetStream();

                    using var readCts = CancellationTokenSource.CreateLinkedTokenSource(serverCt);
                    readCts.CancelAfter(TimeSpan.FromSeconds(5));
                    var requestLine = await ReadRequestLineAsync(stream, readCts.Token).ConfigureAwait(false);
                    if (string.IsNullOrWhiteSpace(requestLine))
                        return;

                    var parts = requestLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2)
                        return;

                    var method = parts[0].ToUpperInvariant();
                    var rawTarget = parts[1];

                    string pathPart;
                    if ((rawTarget.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                         rawTarget.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) &&
                        Uri.TryCreate(rawTarget, UriKind.Absolute, out var absUri))
                    {
                        pathPart = absUri.AbsolutePath;
                    }
                    else
                    {
                        var qIdx = rawTarget.IndexOf('?');
                        pathPart = qIdx >= 0 ? rawTarget[..qIdx] : rawTarget;
                    }

                    var path = pathPart.TrimEnd('/').ToLowerInvariant();

                    using var writeCts = CancellationTokenSource.CreateLinkedTokenSource(serverCt);
                    writeCts.CancelAfter(TimeSpan.FromSeconds(15));

                    if (method == "OPTIONS")
                    {
                        var optionsHeader =
                            "HTTP/1.1 204 No Content\r\n" +
                            "Access-Control-Allow-Origin: *\r\n" +
                            "Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\n" +
                            "Connection: close\r\n\r\n";
                        var optBytes = Encoding.ASCII.GetBytes(optionsHeader);
                        await stream.WriteAsync(optBytes, writeCts.Token).ConfigureAwait(false);
                        await stream.FlushAsync(writeCts.Token).ConfigureAwait(false);
                        return;
                    }

                    if (method != "GET" && method != "HEAD")
                    {
                        var notAllowed =
                            "HTTP/1.1 405 Method Not Allowed\r\n" +
                            "Allow: GET, HEAD, OPTIONS\r\n" +
                            "Content-Length: 0\r\n" +
                            "Connection: close\r\n\r\n";
                        var naBytes = Encoding.ASCII.GetBytes(notAllowed);
                        await stream.WriteAsync(naBytes, writeCts.Token).ConfigureAwait(false);
                        await stream.FlushAsync(writeCts.Token).ConfigureAwait(false);
                        return;
                    }

                    string body;
                    string contentType = "text/plain; charset=utf-8";

                    if (path == "/raw")
                    {
                        lock (_lock)
                        {
                            body = _rawPayload;
                        }
                    }
                    else if (path == "/status")
                    {
                        int count;
                        DateTime? lastUpdatedUtc;
                        lock (_lock)
                        {
                            count = _configCount;
                            lastUpdatedUtc = _lastUpdatedUtc;
                        }

                        contentType = "application/json; charset=utf-8";
                        body = JsonSerializer.Serialize(new
                        {
                            count,
                            lastUpdatedUtc,
                            allowLanAccess = AllowLanAccess,
                            subscriptionUrl = SubscriptionUrl,
                            lanSubscriptionUrl = LanSubscriptionUrl
                        });
                    }
                    else if (path == "" || path == "/sub")
                    {
                        lock (_lock)
                        {
                            body = _base64Payload;
                        }
                    }
                    else
                    {
                        var notFound =
                            "HTTP/1.1 404 Not Found\r\n" +
                            "Content-Length: 0\r\n" +
                            "Connection: close\r\n\r\n";
                        var nfBytes = Encoding.ASCII.GetBytes(notFound);
                        await stream.WriteAsync(nfBytes, writeCts.Token).ConfigureAwait(false);
                        await stream.FlushAsync(writeCts.Token).ConfigureAwait(false);
                        return;
                    }

                    var bodyBytes = Encoding.UTF8.GetBytes(body);
                    var headerText =
                        "HTTP/1.1 200 OK\r\n" +
                        $"Content-Type: {contentType}\r\n" +
                        $"Content-Length: {bodyBytes.Length}\r\n" +
                        "Profile-Title: V2SubAuto\r\n" +
                        "Cache-Control: no-cache\r\n" +
                        "Access-Control-Allow-Origin: *\r\n" +
                        "Connection: close\r\n\r\n";

                    var headerBytes = Encoding.ASCII.GetBytes(headerText);
                    await stream.WriteAsync(headerBytes, writeCts.Token).ConfigureAwait(false);
                    if (method != "HEAD" && bodyBytes.Length > 0)
                    {
                        await stream.WriteAsync(bodyBytes, writeCts.Token).ConfigureAwait(false);
                    }
                    await stream.FlushAsync(writeCts.Token).ConfigureAwait(false);
                }
                catch
                {
                    // Ignore transient client disconnect / malformed request
                }
            }
        }

        private static async Task<string?> ReadRequestLineAsync(NetworkStream stream, CancellationToken ct)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(MaxHeaderBytes);
            try
            {
                int totalRead = 0;

                while (totalRead < MaxHeaderBytes)
                {
                    int n = await stream.ReadAsync(buffer.AsMemory(totalRead, MaxHeaderBytes - totalRead), ct).ConfigureAwait(false);
                    if (n <= 0) break;
                    totalRead += n;

                    if (TryExtractRequestLine(buffer, totalRead, requireHeaderEnd: true, out var requestLine))
                    {
                        return requestLine;
                    }
                }

                return TryExtractRequestLine(buffer, totalRead, requireHeaderEnd: false, out var fallbackLine)
                    ? fallbackLine
                    : null;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private static bool TryExtractRequestLine(byte[] buffer, int totalRead, bool requireHeaderEnd, out string? requestLine)
        {
            requestLine = null;
            if (totalRead <= 0) return false;

            var span = buffer.AsSpan(0, totalRead);
            if (requireHeaderEnd)
            {
                if (span.IndexOf("\r\n\r\n"u8) < 0)
                    return false;

                int firstCrLf = span.IndexOf("\r\n"u8);
                requestLine = firstCrLf >= 0
                    ? Encoding.ASCII.GetString(span[..firstCrLf])
                    : Encoding.ASCII.GetString(span);
                return true;
            }

            int lineEnd = span.IndexOf((byte)'\n');
            var lineSpan = lineEnd >= 0 ? span[..lineEnd] : span;
            requestLine = Encoding.ASCII.GetString(lineSpan).TrimEnd('\r');
            return true;
        }

        public static string? DetectPreferredLanIpv4()
        {
            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(nic => nic.OperationalStatus == OperationalStatus.Up
                                  && nic.NetworkInterfaceType != NetworkInterfaceType.Loopback
                                  && nic.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                    .ToList();

                // Priority 1: Physical Ethernet/Wi-Fi with an IPv4 default gateway and private RFC1918 IP
                foreach (var nic in interfaces)
                {
                    if (IsVirtualAdapter(nic)) continue;
                    var props = nic.GetIPProperties();
                    bool hasIpv4Gateway = props.GatewayAddresses.Any(g =>
                        g.Address.AddressFamily == AddressFamily.InterNetwork &&
                        !IPAddress.Any.Equals(g.Address));
                    if (!hasIpv4Gateway) continue;

                    var ip = props.UnicastAddresses
                        .Select(u => u.Address)
                        .FirstOrDefault(IsPrivateLanIpv4);
                    if (ip != null)
                        return ip.ToString();
                }

                // Priority 2: Any non-virtual adapter with a private RFC1918 IP
                foreach (var nic in interfaces)
                {
                    if (IsVirtualAdapter(nic)) continue;
                    var ip = nic.GetIPProperties().UnicastAddresses
                        .Select(u => u.Address)
                        .FirstOrDefault(IsPrivateLanIpv4);
                    if (ip != null)
                        return ip.ToString();
                }

                // Priority 3: Any active adapter with a non-link-local IPv4
                foreach (var nic in interfaces)
                {
                    var ip = nic.GetIPProperties().UnicastAddresses
                        .Select(u => u.Address)
                        .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !IsLinkLocalIpv4(a));
                    if (ip != null)
                        return ip.ToString();
                }
            }
            catch
            {
                // Fall back to UDP route probe
            }

            try
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                socket.Connect("8.8.8.8", 65530);
                if (socket.LocalEndPoint is IPEndPoint ep && !IPAddress.IsLoopback(ep.Address))
                    return ep.Address.ToString();
            }
            catch { }

            return null;
        }

        private static bool IsVirtualAdapter(NetworkInterface nic)
        {
            var combined = $"{nic.Name} {nic.Description}".ToLowerInvariant();
            return VirtualAdapterKeywords.Any(k => combined.Contains(k, StringComparison.Ordinal));
        }

        private static bool IsPrivateLanIpv4(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
            var b = ip.GetAddressBytes();
            return b[0] == 192 && b[1] == 168
                || b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31);
        }

        private static bool IsLinkLocalIpv4(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
            var b = ip.GetAddressBytes();
            return b[0] == 169 && b[1] == 254;
        }

        public void Dispose() => Stop();
    }
}
