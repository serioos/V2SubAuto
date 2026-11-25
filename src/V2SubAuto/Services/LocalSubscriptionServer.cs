using System;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace V2SubAuto.Services
{
    /// <summary>
    /// Lightweight local HTTP server serving surviving configs for V2RayN Subscription Group.
    /// Endpoints:
    ///   GET /sub    -> Base64-encoded share URI list (standard V2RayN subscription format)
    ///   GET /raw    -> Plain-text newline-separated share URI list
    ///   GET /status -> JSON metadata (count, lastUpdatedUtc)
    /// </summary>
    public sealed class LocalSubscriptionServer : IDisposable
    {
        private HttpListener? _listener;
        private CancellationTokenSource? _cts;
        private Task? _loopTask;

        private readonly object _lock = new();
        private string _base64Payload = string.Empty;
        private string _rawPayload = string.Empty;
        private int _configCount;
        private DateTime? _lastUpdatedUtc;

        public int Port { get; private set; }
        public bool IsRunning => _listener?.IsListening == true;
        public string SubscriptionUrl => $"http://127.0.0.1:{Port}/sub";
        public string RawUrl => $"http://127.0.0.1:{Port}/raw";

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

        public bool Start(int port)
        {
            Stop();
            Port = port;

            try
            {
                _listener = new HttpListener();
                _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
                _listener.Start();

                _cts = new CancellationTokenSource();
                _loopTask = Task.Run(() => ListenLoopAsync(_cts.Token));
                OnLog?.Invoke($"Local subscription server listening at {SubscriptionUrl}");
                return true;
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"Failed to start local server on port {port}: {ex.Message}");
                Stop();
                return false;
            }
        }

        public void Stop()
        {
            try { _cts?.Cancel(); } catch { }
            try { _listener?.Stop(); } catch { }
            try { _listener?.Close(); } catch { }
            _listener = null;
            _cts?.Dispose();
            _cts = null;
        }

        private async Task ListenLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && _listener is { IsListening: true })
            {
                HttpListenerContext ctx;
                try
                {
                    ctx = await _listener.GetContextAsync().ConfigureAwait(false);
                }
                catch
                {
                    break;
                }

                _ = Task.Run(() => HandleRequestAsync(ctx), ct);
            }
        }

        private async Task HandleRequestAsync(HttpListenerContext ctx)
        {
            try
            {
                var path = (ctx.Request.Url?.AbsolutePath ?? "/").TrimEnd('/').ToLowerInvariant();
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
                            subscriptionUrl = SubscriptionUrl
                        });
                    }
                    else
                    {
                        // Default & /sub -> Base64 subscription for V2RayN
                        body = _base64Payload;
                    }
                }

                var bytes = Encoding.UTF8.GetBytes(body);
                ctx.Response.StatusCode = 200;
                ctx.Response.ContentType = contentType;
                ctx.Response.Headers["Profile-Title"] = "V2SubAuto";
                ctx.Response.Headers["Cache-Control"] = "no-cache";
                ctx.Response.ContentLength64 = bytes.Length;
                await ctx.Response.OutputStream.WriteAsync(bytes).ConfigureAwait(false);
                ctx.Response.OutputStream.Close();
            }
            catch
            {
                try { ctx.Response.Abort(); } catch { }
            }
        }

        public void Dispose() => Stop();
    }
}
