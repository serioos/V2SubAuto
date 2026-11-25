using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using V2SubAuto.Models;

namespace V2SubAuto.Services
{
    public static class NodeParser
    {
        public static List<ProxyNode> ParseSubscriptionContent(string rawText, string sourceName)
        {
            var results = new List<ProxyNode>();
            if (string.IsNullOrWhiteSpace(rawText))
                return results;

            var trimmed = rawText.Trim();
            string decoded = trimmed;

            // If it does not directly contain protocol schemes, try Base64 decoding
            if (!LooksLikeUriList(trimmed))
            {
                var maybeDecoded = TryDecodeBase64(trimmed);
                if (!string.IsNullOrWhiteSpace(maybeDecoded) && LooksLikeUriList(maybeDecoded))
                {
                    decoded = maybeDecoded;
                }
            }

            var lines = decoded.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var rawLine in lines)
            {
                var line = rawLine.Trim();
                if (string.IsNullOrEmpty(line) || line.StartsWith('#'))
                    continue;

                var node = ParseSingleUri(line, sourceName);
                if (node != null && !string.IsNullOrWhiteSpace(node.Address) && node.Port > 0 && node.Port <= 65535)
                {
                    results.Add(node);
                }
            }

            return results;
        }

        public static ProxyNode? ParseSingleUri(string uri, string sourceName = "")
        {
            try
            {
                if (uri.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
                    return ParseVmess(uri, sourceName);
                if (uri.StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
                    return ParseVless(uri, sourceName);
                if (uri.StartsWith("trojan://", StringComparison.OrdinalIgnoreCase))
                    return ParseTrojan(uri, sourceName);
                if (uri.StartsWith("ss://", StringComparison.OrdinalIgnoreCase))
                    return ParseShadowsocks(uri, sourceName);
                if (uri.StartsWith("hysteria2://", StringComparison.OrdinalIgnoreCase) ||
                    uri.StartsWith("hy2://", StringComparison.OrdinalIgnoreCase))
                    return ParseHysteria2(uri, sourceName);
                if (uri.StartsWith("tuic://", StringComparison.OrdinalIgnoreCase))
                    return ParseTuic(uri, sourceName);
                if (uri.StartsWith("socks://", StringComparison.OrdinalIgnoreCase))
                    return ParseSocks(uri, sourceName);
                if (uri.StartsWith("wireguard://", StringComparison.OrdinalIgnoreCase))
                    return ParseWireGuard(uri, sourceName);
            }
            catch
            {
                // Skip malformed URI
            }

            return null;
        }

        private static ProxyNode? ParseVmess(string rawUri, string sourceName)
        {
            var payload = rawUri.Substring("vmess://".Length).Trim();
            var jsonStr = TryDecodeBase64(payload);
            if (string.IsNullOrWhiteSpace(jsonStr))
                return null;

            using var doc = JsonDocument.Parse(jsonStr);
            var root = doc.RootElement;

            var address = GetJsonString(root, "add");
            var port = GetJsonInt(root, "port");
            var id = GetJsonString(root, "id");
            if (string.IsNullOrWhiteSpace(address) || port <= 0 || string.IsNullOrWhiteSpace(id))
                return null;

            var net = NormalizeNetwork(GetJsonString(root, "net", "tcp"));
            var headerType = GetJsonString(root, "type");
            var host = GetJsonString(root, "host");
            var path = GetJsonString(root, "path");
            var tls = GetJsonString(root, "tls");
            var sni = GetJsonString(root, "sni");

            var node = new ProxyNode
            {
                RawUri = rawUri,
                SourceName = sourceName,
                Protocol = ProxyProtocol.Vmess,
                Remarks = GetJsonString(root, "ps", $"{address}:{port}"),
                Address = address,
                Port = port,
                Password = id,
                VmessAlterId = GetJsonInt(root, "aid"),
                VmessSecurity = GetJsonString(root, "scy", "auto"),
                Network = net,
                StreamSecurity = string.Equals(tls, "tls", StringComparison.OrdinalIgnoreCase) ? "tls" : string.Empty,
                Sni = !string.IsNullOrWhiteSpace(sni) ? sni : host,
                Alpn = GetJsonString(root, "alpn"),
                Fingerprint = GetJsonString(root, "fp"),
                AllowInsecure = GetJsonBool(root, "insecure") || GetJsonBool(root, "allowInsecure")
            };

            var grpcMode = string.Equals(net, "grpc", StringComparison.OrdinalIgnoreCase) ? headerType : string.Empty;
            ApplyTransportFields(node, net, headerType, host, path, string.Empty, string.Empty, grpcMode, string.Empty);
            return node;
        }

        private static ProxyNode? ParseVless(string rawUri, string sourceName)
        {
            var uri = new Uri(rawUri);
            var query = ParseQuery(uri.Query);
            var remarks = DecodeFragment(uri.Fragment, $"{uri.Host}:{uri.Port}");
            var net = NormalizeNetwork(GetQuery(query, "type", "tcp"));
            var security = GetQuery(query, "security", string.Empty).ToLowerInvariant();
            if (security == "none") security = string.Empty;

            var node = new ProxyNode
            {
                RawUri = rawUri,
                SourceName = sourceName,
                Protocol = ProxyProtocol.Vless,
                Remarks = remarks,
                Address = UnwrapIpv6(uri.Host),
                Port = uri.Port,
                Password = Uri.UnescapeDataString(uri.UserInfo),
                VlessEncryption = GetQuery(query, "encryption", "none"),
                Flow = GetQuery(query, "flow", string.Empty),
                Network = net,
                StreamSecurity = security,
                Sni = GetQuery(query, "sni", GetQuery(query, "peer", string.Empty)),
                Alpn = GetQuery(query, "alpn", string.Empty),
                Fingerprint = GetQuery(query, "fp", string.Empty),
                PublicKey = GetQuery(query, "pbk", string.Empty),
                ShortId = GetQuery(query, "sid", string.Empty),
                SpiderX = GetQuery(query, "spx", string.Empty),
                AllowInsecure = IsTrue(GetQuery(query, "allowInsecure", GetQuery(query, "insecure", "0")))
            };

            ApplyTransportFields(
                node,
                net,
                GetQuery(query, "headerType", string.Empty),
                GetQuery(query, "host", string.Empty),
                GetQuery(query, "path", string.Empty),
                GetQuery(query, "serviceName", string.Empty),
                GetQuery(query, "authority", string.Empty),
                GetQuery(query, "mode", string.Empty),
                GetQuery(query, "extra", GetQuery(query, "seed", string.Empty)));

            return node;
        }

        private static ProxyNode? ParseTrojan(string rawUri, string sourceName)
        {
            var uri = new Uri(rawUri);
            var query = ParseQuery(uri.Query);
            var remarks = DecodeFragment(uri.Fragment, $"{uri.Host}:{uri.Port}");
            var net = NormalizeNetwork(GetQuery(query, "type", "tcp"));
            var security = GetQuery(query, "security", "tls").ToLowerInvariant();
            if (security == "none") security = string.Empty;

            var node = new ProxyNode
            {
                RawUri = rawUri,
                SourceName = sourceName,
                Protocol = ProxyProtocol.Trojan,
                Remarks = remarks,
                Address = UnwrapIpv6(uri.Host),
                Port = uri.Port,
                Password = Uri.UnescapeDataString(uri.UserInfo),
                Flow = GetQuery(query, "flow", string.Empty),
                Network = net,
                StreamSecurity = security,
                Sni = GetQuery(query, "sni", GetQuery(query, "peer", string.Empty)),
                Alpn = GetQuery(query, "alpn", string.Empty),
                Fingerprint = GetQuery(query, "fp", string.Empty),
                PublicKey = GetQuery(query, "pbk", string.Empty),
                ShortId = GetQuery(query, "sid", string.Empty),
                SpiderX = GetQuery(query, "spx", string.Empty),
                AllowInsecure = IsTrue(GetQuery(query, "allowInsecure", GetQuery(query, "insecure", "0")))
            };

            ApplyTransportFields(
                node,
                net,
                GetQuery(query, "headerType", string.Empty),
                GetQuery(query, "host", string.Empty),
                GetQuery(query, "path", string.Empty),
                GetQuery(query, "serviceName", string.Empty),
                GetQuery(query, "authority", string.Empty),
                GetQuery(query, "mode", string.Empty),
                GetQuery(query, "extra", GetQuery(query, "seed", string.Empty)));

            return node;
        }

        private static ProxyNode? ParseShadowsocks(string rawUri, string sourceName)
        {
            var body = rawUri.Substring("ss://".Length);
            string remarks = string.Empty;
            var hashIdx = body.IndexOf('#');
            if (hashIdx >= 0)
            {
                remarks = Uri.UnescapeDataString(body[(hashIdx + 1)..]);
                body = body[..hashIdx];
            }

            // Strip optional plugin query
            var qIdx = body.IndexOf('?');
            if (qIdx >= 0)
            {
                body = body[..qIdx];
            }

            string method, password, host;
            int port;

            var atIdx = body.LastIndexOf('@');
            if (atIdx >= 0)
            {
                var userInfoPart = body[..atIdx];
                var hostPortPart = body[(atIdx + 1)..];
                if (!userInfoPart.Contains(':'))
                {
                    userInfoPart = TryDecodeBase64(userInfoPart) ?? userInfoPart;
                }
                else
                {
                    userInfoPart = Uri.UnescapeDataString(userInfoPart);
                }

                var colon = userInfoPart.IndexOf(':');
                if (colon <= 0) return null;
                method = userInfoPart[..colon];
                password = userInfoPart[(colon + 1)..];

                if (!TrySplitHostPort(hostPortPart, out host, out port))
                    return null;
            }
            else
            {
                var decoded = TryDecodeBase64(body);
                if (string.IsNullOrWhiteSpace(decoded)) return null;
                var decAt = decoded.LastIndexOf('@');
                if (decAt <= 0) return null;
                var userInfo = decoded[..decAt];
                var hostPort = decoded[(decAt + 1)..];
                var colon = userInfo.IndexOf(':');
                if (colon <= 0) return null;
                method = userInfo[..colon];
                password = userInfo[(colon + 1)..];

                if (!TrySplitHostPort(hostPort, out host, out port))
                    return null;
            }

            return new ProxyNode
            {
                RawUri = rawUri,
                SourceName = sourceName,
                Protocol = ProxyProtocol.Shadowsocks,
                Remarks = string.IsNullOrWhiteSpace(remarks) ? $"{host}:{port}" : remarks,
                Address = host,
                Port = port,
                SsMethod = method,
                Password = password,
                Network = "tcp"
            };
        }

        private static ProxyNode? ParseHysteria2(string rawUri, string sourceName)
        {
            var normalized = rawUri.StartsWith("hy2://", StringComparison.OrdinalIgnoreCase)
                ? "hysteria2://" + rawUri.Substring("hy2://".Length)
                : rawUri;

            var uri = new Uri(normalized);
            var query = ParseQuery(uri.Query);
            var remarks = DecodeFragment(uri.Fragment, $"{uri.Host}:{uri.Port}");

            return new ProxyNode
            {
                RawUri = rawUri,
                SourceName = sourceName,
                Protocol = ProxyProtocol.Hysteria2,
                Remarks = remarks,
                Address = UnwrapIpv6(uri.Host),
                Port = uri.Port > 0 ? uri.Port : 443,
                Password = Uri.UnescapeDataString(uri.UserInfo),
                SalamanderPass = GetQuery(query, "obfs-password", string.Empty),
                StreamSecurity = "tls",
                Sni = GetQuery(query, "sni", UnwrapIpv6(uri.Host)),
                Alpn = GetQuery(query, "alpn", string.Empty),
                AllowInsecure = IsTrue(GetQuery(query, "insecure", GetQuery(query, "allowInsecure", "0")))
            };
        }

        private static ProxyNode? ParseTuic(string rawUri, string sourceName)
        {
            var uri = new Uri(rawUri);
            var query = ParseQuery(uri.Query);
            var remarks = DecodeFragment(uri.Fragment, $"{uri.Host}:{uri.Port}");

            var userInfo = Uri.UnescapeDataString(uri.UserInfo);
            var parts = userInfo.Split(':', 2);
            var uuid = parts.Length > 0 ? parts[0] : string.Empty;
            var password = parts.Length > 1 ? parts[1] : string.Empty;

            return new ProxyNode
            {
                RawUri = rawUri,
                SourceName = sourceName,
                Protocol = ProxyProtocol.Tuic,
                Remarks = remarks,
                Address = UnwrapIpv6(uri.Host),
                Port = uri.Port > 0 ? uri.Port : 443,
                Username = uuid,
                Password = password,
                CongestionControl = GetQuery(query, "congestion_control", "bbr"),
                StreamSecurity = "tls",
                Sni = GetQuery(query, "sni", UnwrapIpv6(uri.Host)),
                Alpn = GetQuery(query, "alpn", "h3"),
                AllowInsecure = IsTrue(GetQuery(query, "allow_insecure", GetQuery(query, "insecure", "0")))
            };
        }

        private static ProxyNode? ParseSocks(string rawUri, string sourceName)
        {
            var uri = new Uri(rawUri);
            var remarks = DecodeFragment(uri.Fragment, $"{uri.Host}:{uri.Port}");
            string user = string.Empty, pass = string.Empty;

            if (!string.IsNullOrEmpty(uri.UserInfo))
            {
                var info = uri.UserInfo;
                if (!info.Contains(':'))
                {
                    info = TryDecodeBase64(info) ?? info;
                }
                var parts = info.Split(':', 2);
                user = Uri.UnescapeDataString(parts[0]);
                if (parts.Length > 1) pass = Uri.UnescapeDataString(parts[1]);
            }

            return new ProxyNode
            {
                RawUri = rawUri,
                SourceName = sourceName,
                Protocol = ProxyProtocol.Socks,
                Remarks = remarks,
                Address = UnwrapIpv6(uri.Host),
                Port = uri.Port,
                Username = user,
                Password = pass
            };
        }

        private static ProxyNode? ParseWireGuard(string rawUri, string sourceName)
        {
            // Manual parsing handles unescaped '/' and '+' inside Base64 WireGuard private keys
            var body = rawUri.Substring("wireguard://".Length);
            string fragment = string.Empty;
            var hashIdx = body.IndexOf('#');
            if (hashIdx >= 0)
            {
                fragment = body[hashIdx..];
                body = body[..hashIdx];
            }

            string queryPart = string.Empty;
            var qIdx = body.IndexOf('?');
            if (qIdx >= 0)
            {
                queryPart = body[qIdx..];
                body = body[..qIdx];
            }

            var atIdx = body.LastIndexOf('@');
            if (atIdx <= 0)
                return null;

            var privateKey = Uri.UnescapeDataString(body[..atIdx]).Trim();
            var hostPortPart = body[(atIdx + 1)..];
            if (!TrySplitHostPort(hostPortPart, out var host, out var port))
                return null;

            var query = ParseQuery(queryPart);
            var remarks = DecodeFragment(fragment, $"{host}:{port}");

            int.TryParse(GetQuery(query, "mtu", "1280"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var mtu);
            if (mtu <= 0) mtu = 1280;

            return new ProxyNode
            {
                RawUri = rawUri,
                SourceName = sourceName,
                Protocol = ProxyProtocol.WireGuard,
                Remarks = remarks,
                Address = UnwrapIpv6(host),
                Port = port,
                Password = privateKey,
                PublicKey = GetQuery(query, "publickey", string.Empty),
                WgReserved = GetQuery(query, "reserved", string.Empty),
                WgLocalAddress = GetQuery(query, "address", "172.16.0.2/32"),
                WgMtu = mtu
            };
        }

        /// <summary>
        /// Returns the node's share URI, optionally appending latency and speed metrics to remarks.
        /// </summary>
        public static string FormatExportUri(ProxyNode node, bool appendMetrics)
        {
            if (!appendMetrics)
                return node.RawUri;

            string tag;
            if (node.RealDelayMs > 0 && node.DownloadSpeedMBps > 0)
                tag = string.Create(CultureInfo.InvariantCulture, $"[{node.RealDelayMs}ms | {node.DownloadSpeedMBps:0.0}MB/s]");
            else if (node.RealDelayMs > 0)
                tag = string.Create(CultureInfo.InvariantCulture, $"[{node.RealDelayMs}ms]");
            else if (node.TcpingMs > 0)
                tag = string.Create(CultureInfo.InvariantCulture, $"[tcp:{node.TcpingMs}ms]");
            else
                return node.RawUri;

            if (node.Protocol == ProxyProtocol.Vmess && node.RawUri.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var decoded = TryDecodeBase64(node.RawUri.Substring("vmess://".Length));
                    if (!string.IsNullOrWhiteSpace(decoded))
                    {
                        var jsonNode = JsonNode.Parse(decoded)?.AsObject();
                        if (jsonNode != null)
                        {
                            var oldPs = jsonNode["ps"]?.GetValue<string>() ?? node.Remarks;
                            jsonNode["ps"] = $"{oldPs} {tag}".Trim();
                            var updated = Convert.ToBase64String(Encoding.UTF8.GetBytes(jsonNode.ToJsonString()));
                            return "vmess://" + updated;
                        }
                    }
                }
                catch
                {
                    return node.RawUri;
                }
            }

            var hashIdx = node.RawUri.IndexOf('#');
            var basePart = hashIdx >= 0 ? node.RawUri[..hashIdx] : node.RawUri;
            var newRemark = $"{node.Remarks} {tag}".Trim();
            return $"{basePart}#{Uri.EscapeDataString(newRemark)}";
        }

        private static void ApplyTransportFields(
            ProxyNode node, string net, string headerType, string host, string path,
            string serviceName, string authority, string mode, string extraOrSeed)
        {
            switch (net)
            {
                case "tcp":
                    node.RawHeaderType = headerType;
                    node.Host = host;
                    node.Path = path;
                    break;
                case "ws":
                case "httpupgrade":
                case "h2":
                    node.Host = host;
                    node.Path = string.IsNullOrEmpty(path) ? "/" : path;
                    break;
                case "xhttp":
                case "splithttp":
                    node.Host = host;
                    node.Path = string.IsNullOrEmpty(path) ? "/" : path;
                    node.XhttpMode = mode;
                    node.XhttpExtra = extraOrSeed;
                    break;
                case "grpc":
                    node.GrpcServiceName = !string.IsNullOrEmpty(serviceName) ? serviceName : path;
                    node.GrpcAuthority = authority;
                    node.GrpcMode = string.IsNullOrEmpty(mode) ? "gun" : mode;
                    break;
                case "kcp":
                    node.KcpHeaderType = headerType;
                    node.KcpSeed = !string.IsNullOrEmpty(extraOrSeed) ? extraOrSeed : path;
                    break;
                default:
                    node.Host = host;
                    node.Path = path;
                    break;
            }
        }

        private static string NormalizeNetwork(string net)
        {
            var n = (net ?? "tcp").Trim().ToLowerInvariant();
            return n switch
            {
                "" or "raw" => "tcp",
                "http" => "h2",
                _ => n
            };
        }

        private static bool LooksLikeUriList(string text)
        {
            return text.Contains("vmess://", StringComparison.OrdinalIgnoreCase)
                || text.Contains("vless://", StringComparison.OrdinalIgnoreCase)
                || text.Contains("trojan://", StringComparison.OrdinalIgnoreCase)
                || text.Contains("ss://", StringComparison.OrdinalIgnoreCase)
                || text.Contains("hy2://", StringComparison.OrdinalIgnoreCase)
                || text.Contains("hysteria2://", StringComparison.OrdinalIgnoreCase)
                || text.Contains("tuic://", StringComparison.OrdinalIgnoreCase)
                || text.Contains("socks://", StringComparison.OrdinalIgnoreCase)
                || text.Contains("wireguard://", StringComparison.OrdinalIgnoreCase);
        }

        public static string? TryDecodeBase64(string input)
        {
            try
            {
                var s = input.Trim().Replace("\r", "").Replace("\n", "").Replace(" ", "");
                s = s.Replace('-', '+').Replace('_', '/');
                var mod = s.Length % 4;
                if (mod > 0) s = s.PadRight(s.Length + (4 - mod), '=');
                var bytes = Convert.FromBase64String(s);
                return Encoding.UTF8.GetString(bytes);
            }
            catch
            {
                return null;
            }
        }

        private static Dictionary<string, string> ParseQuery(string query)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(query)) return dict;
            var q = query.TrimStart('?');
            foreach (var pair in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var kv = pair.Split('=', 2);
                var key = Uri.UnescapeDataString(kv[0]);
                // Preserve literal '+' characters (common in Base64 publickey/pbk/reserved parameters)
                var val = kv.Length > 1 ? Uri.UnescapeDataString(kv[1]) : string.Empty;
                dict[key] = val;
            }
            return dict;
        }

        private static string GetQuery(Dictionary<string, string> q, string key, string fallback)
            => q.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v) ? v : fallback;

        private static string DecodeFragment(string fragment, string fallback)
        {
            var f = fragment.TrimStart('#');
            if (string.IsNullOrWhiteSpace(f)) return fallback;
            try { return Uri.UnescapeDataString(f); } catch { return f; }
        }

        private static string UnwrapIpv6(string host)
            => host.Length >= 2 && host[0] == '[' && host[^1] == ']' ? host[1..^1] : host;

        private static bool TrySplitHostPort(string hostPort, out string host, out int port)
        {
            host = string.Empty;
            port = 0;
            hostPort = hostPort.Trim().TrimEnd('/');
            if (hostPort.StartsWith('['))
            {
                var closeIdx = hostPort.IndexOf(']');
                if (closeIdx < 0 || closeIdx + 2 > hostPort.Length || hostPort[closeIdx + 1] != ':')
                    return false;
                host = hostPort[1..closeIdx];
                return int.TryParse(hostPort[(closeIdx + 2)..], out port);
            }

            var colon = hostPort.LastIndexOf(':');
            if (colon <= 0) return false;
            host = hostPort[..colon];
            return int.TryParse(hostPort[(colon + 1)..], out port);
        }

        private static bool IsTrue(string value)
            => value == "1" || string.Equals(value, "true", StringComparison.OrdinalIgnoreCase);

        private static string GetJsonString(JsonElement el, string prop, string fallback = "")
        {
            if (!el.TryGetProperty(prop, out var v)) return fallback;
            return v.ValueKind switch
            {
                JsonValueKind.String => v.GetString() ?? fallback,
                JsonValueKind.Number => v.GetRawText(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                _ => fallback
            };
        }

        private static int GetJsonInt(JsonElement el, string prop, int fallback = 0)
        {
            if (!el.TryGetProperty(prop, out var v)) return fallback;
            if (v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var n)) return n;
            if (v.ValueKind == JsonValueKind.String && int.TryParse(v.GetString(), out var parsed)) return parsed;
            return fallback;
        }

        private static bool GetJsonBool(JsonElement el, string prop)
        {
            if (!el.TryGetProperty(prop, out var v)) return false;
            if (v.ValueKind == JsonValueKind.True) return true;
            if (v.ValueKind == JsonValueKind.String) return IsTrue(v.GetString() ?? "");
            if (v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var n)) return n != 0;
            return false;
        }
    }
}
