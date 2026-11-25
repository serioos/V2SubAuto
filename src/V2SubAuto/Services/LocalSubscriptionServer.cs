using System;
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
                _listener = new TcpListener(bindAddress, port);
                _listener.Start();
                _isRunning = true;

                _cts = new CancellationTokenSource();
                _loopTask = Task.Run(() => ListenLoopAsync(_cts.Token));

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
            try { _cts?.Cancel(); } catch { }
            try { _listener?.Stop(); } catch { }
            _listener = null;
            _cts?.Dispose();
            _cts = null;
        }

        private async Task ListenLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && _listener != null)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                }
                catch
                {
                    break;
                }

                _ = Task.Run(() => HandleClientAsync(client), ct);
            }
        }

        private async Task HandleClientAsync(TcpClient client)
        {
            using (client)
            {
                try
                {
                    client.ReceiveTimeout = 5000;
                    client.SendTimeout = 10000;
                    await using var stream = client.GetStream();

                    using var readCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    var requestLine = await ReadRequestLineAsync(stream, readCts.Token).ConfigureAwait(false);
                    if (string.IsNullOrWhiteSpace(requestLine))
                        return;

                    var parts = requestLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2)
                        return;

                    var method = parts[0].ToUpperInvariant();
                    var rawTarget = parts[1];

                    // Strip query string if present
                    var qIdx = rawTarget.IndexOf('?');
                    var pathPart = qIdx >= 0 ? rawTarget[..qIdx] : rawTarget;
                    var path = pathPart.TrimEnd('/').ToLowerInvariant();

                    if (method == "OPTIONS")
                    {
                        var optionsHeader =
                            "HTTP/1.1 204 No Content\r\n" +
                            "Access-Control-Allow-Origin: *\r\n" +
                            "Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\n" +
                            "Connection: close\r\n\r\n";
                        var optBytes = Encoding.ASCII.GetBytes(optionsHeader);
                        await stream.WriteAsync(optBytes, readCts.Token).ConfigureAwait(false);
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
                        await stream.WriteAsync(naBytes, readCts.Token).ConfigureAwait(false);
                        return;
                    }

                    string body;
                    string contentType = "text/plain; charset=utf-8";

                    lock (_lock)
                    {
                        if (path == "/raw")
                        {
                            body = _rawPayload;
                        }
                        else if (path == "/status")
                        {
                            contentType = "application/json; charset=utf-8";
                            body = JsonSerializer.Serialize(new
                            {
                                count = _configCount,
                                lastUpdatedUtc = _lastUpdatedUtc,
                                allowLanAccess = AllowLanAccess,
                                subscriptionUrl = SubscriptionUrl,
                                lanSubscriptionUrl = LanSubscriptionUrl
                            });
                        }
                        else
                        {
                            // Default & /sub -> Base64 subscription for V2RayN & mobile clients
                            body = _base64Payload;
                        }
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
                    await stream.WriteAsync(headerBytes, readCts.Token).ConfigureAwait(false);
                    if (method != "HEAD" && bodyBytes.Length > 0)
                    {
                        await stream.WriteAsync(bodyBytes, readCts.Token).ConfigureAwait(false);
                    }
                    await stream.FlushAsync(readCts.Token).ConfigureAwait(false);
                }
                catch
                {
                    // Ignore transient client disconnect / malformed request
                }
            }
        }

        private static async Task<string?> ReadRequestLineAsync(NetworkStream stream, CancellationToken ct)
        {
            var buffer = new byte[4096];
            int totalRead = 0;

            while (totalRead < buffer.Length)
            {
                int n = await stream.ReadAsync(buffer.AsMemory(totalRead, buffer.Length - totalRead), ct).ConfigureAwait(false);
                if (n <= 0) break;
                totalRead += n;

                // Stop as soon as we see the end of HTTP headers (\r\n\r\n) or at least the request line (\r\n)
                var text = Encoding.ASCII.GetString(buffer, 0, totalRead);
                int headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                if (headerEnd >= 0)
                {
                    int firstCrLf = text.IndexOf("\r\n", StringComparison.Ordinal);
                    return firstCrLf >= 0 ? text[..firstCrLf] : text;
                }
            }

            if (totalRead == 0) return null;
            var fallback = Encoding.ASCII.GetString(buffer, 0, totalRead);
            int lineEnd = fallback.IndexOf('\n');
            return (lineEnd >= 0 ? fallback[..lineEnd] : fallback).TrimEnd('\r');
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
