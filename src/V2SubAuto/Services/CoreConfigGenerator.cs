using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text.Json.Nodes;
using V2SubAuto.Models;

namespace V2SubAuto.Services
{
    public static class PortAllocator
    {
        private const int MinPort = 20000;
        private const int MaxPort = 48000;

        private static readonly object LockObj = new();
        private static readonly HashSet<int> LeasedPorts = new();
        private static int _cursor = MinPort;

        public static List<int> AllocatePorts(int count)
        {
            var allocated = new List<int>(count);
            if (count <= 0) return allocated;

            lock (LockObj)
            {
                var used = new HashSet<int>(LeasedPorts);
                try
                {
                    var props = IPGlobalProperties.GetIPGlobalProperties();
                    foreach (var ep in props.GetActiveTcpListeners()) used.Add(ep.Port);
                    foreach (var ep in props.GetActiveUdpListeners()) used.Add(ep.Port);
                    foreach (var conn in props.GetActiveTcpConnections()) used.Add(conn.LocalEndPoint.Port);
                }
                catch
                {
                    // Ignore OS query errors and rely on leased set + cursor
                }

                int rangeSize = MaxPort - MinPort + 1;
                int attempts = 0;
                while (allocated.Count < count && attempts < rangeSize)
                {
                    attempts++;
                    _cursor++;
                    if (_cursor > MaxPort) _cursor = MinPort;
                    if (!used.Contains(_cursor))
                    {
                        used.Add(_cursor);
                        LeasedPorts.Add(_cursor);
                        allocated.Add(_cursor);
                    }
                }

                // If we couldn't satisfy the entire request, release partial leases
                if (allocated.Count < count)
                {
                    foreach (var p in allocated) LeasedPorts.Remove(p);
                    allocated.Clear();
                }
            }
            return allocated;
        }

        public static void ReleasePorts(IEnumerable<int>? ports)
        {
            if (ports == null) return;
            lock (LockObj)
            {
                foreach (var p in ports)
                {
                    LeasedPorts.Remove(p);
                }
            }
        }
    }

    public static class CoreConfigGenerator
    {
        private static readonly HashSet<string> ValidXrayNetworks = new(StringComparer.OrdinalIgnoreCase)
        {
            "tcp", "ws", "grpc", "h2", "httpupgrade", "xhttp", "splithttp", "kcp"
        };

        private static readonly HashSet<string> ValidXraySsMethods = new(StringComparer.OrdinalIgnoreCase)
        {
            "aes-128-gcm", "aes-256-gcm",
            "chacha20-poly1305", "chacha20-ietf-poly1305",
            "xchacha20-poly1305", "xchacha20-ietf-poly1305",
            "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
            "none", "plain"
        };

        private static readonly HashSet<string> ValidVmessSecurity = new(StringComparer.OrdinalIgnoreCase)
        {
            "auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"
        };

        private static readonly HashSet<string> ValidVlessFlows = new(StringComparer.OrdinalIgnoreCase)
        {
            "", "xtls-rprx-vision", "xtls-rprx-vision-udp443"
        };

        private static readonly HashSet<string> ValidFingerprints = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"
        };

        private static readonly HashSet<string> ValidXhttpModes = new(StringComparer.OrdinalIgnoreCase)
        {
            "auto", "packet-up", "stream-up", "stream-one"
        };

        /// <summary>
        /// Cheap structural validation used before Tcping so malformed nodes never waste sockets.
        /// </summary>
        public static bool IsStructurallyValid(ProxyNode n)
        {
            if (string.IsNullOrWhiteSpace(n.Address) || n.Port <= 0 || n.Port > 65535)
                return false;

            return n.CoreType == CoreEngineType.Xray
                ? BuildXrayOutbound(n, "check") != null
                : (n.Protocol == ProxyProtocol.WireGuard
                    ? BuildSingboxWireGuardEndpoint(n, "check") != null
                    : BuildSingboxOutbound(n, "check") != null);
        }

        public static string? GenerateXraySpeedtestConfig(IList<ProxyNode> nodes, out List<ProxyNode> testableNodes)
        {
            testableNodes = new List<ProxyNode>();
            var ports = PortAllocator.AllocatePorts(nodes.Count);
            if (ports.Count < nodes.Count)
                return null;

            var inbounds = new JsonArray();
            var outbounds = new JsonArray();
            var rules = new JsonArray();
            var unusedPorts = new List<int>();

            for (int i = 0; i < nodes.Count; i++)
            {
                var node = nodes[i];
                var port = ports[i];
                var outboundTag = $"proxy{port}";
                var inboundTag = $"mixed{port}";

                var outbound = BuildXrayOutbound(node, outboundTag);
                if (outbound == null)
                {
                    unusedPorts.Add(port);
                    continue;
                }

                node.LocalTestPort = port;
                testableNodes.Add(node);

                inbounds.Add(new JsonObject
                {
                    ["tag"] = inboundTag,
                    ["listen"] = "127.0.0.1",
                    ["port"] = port,
                    ["protocol"] = "mixed",
                    ["settings"] = new JsonObject
                    {
                        ["auth"] = "noauth",
                        ["udp"] = true
                    }
                });

                outbounds.Add(outbound);

                rules.Add(new JsonObject
                {
                    ["type"] = "field",
                    ["inboundTag"] = new JsonArray { inboundTag },
                    ["outboundTag"] = outboundTag
                });
            }

            if (unusedPorts.Count > 0)
            {
                PortAllocator.ReleasePorts(unusedPorts);
            }

            if (testableNodes.Count == 0)
                return null;

            outbounds.Add(new JsonObject
            {
                ["tag"] = "direct",
                ["protocol"] = "freedom"
            });

            var root = new JsonObject
            {
                ["log"] = new JsonObject { ["loglevel"] = "none" },
                ["inbounds"] = inbounds,
                ["outbounds"] = outbounds,
                ["routing"] = new JsonObject
                {
                    ["domainStrategy"] = "AsIs",
                    ["rules"] = rules
                }
            };

            return root.ToJsonString();
        }

        public static string? GenerateSingboxSpeedtestConfig(IList<ProxyNode> nodes, out List<ProxyNode> testableNodes)
        {
            testableNodes = new List<ProxyNode>();
            var ports = PortAllocator.AllocatePorts(nodes.Count);
            if (ports.Count < nodes.Count)
                return null;

            var inbounds = new JsonArray();
            var outbounds = new JsonArray();
            var endpoints = new JsonArray();
            var rules = new JsonArray();
            var unusedPorts = new List<int>();

            for (int i = 0; i < nodes.Count; i++)
            {
                var node = nodes[i];
                var port = ports[i];
                var targetTag = $"proxy{port}";
                var inboundTag = $"mixed{port}";

                if (node.Protocol == ProxyProtocol.WireGuard)
                {
                    var endpoint = BuildSingboxWireGuardEndpoint(node, targetTag);
                    if (endpoint == null)
                    {
                        unusedPorts.Add(port);
                        continue;
                    }
                    endpoints.Add(endpoint);
                }
                else
                {
                    var outbound = BuildSingboxOutbound(node, targetTag);
                    if (outbound == null)
                    {
                        unusedPorts.Add(port);
                        continue;
                    }
                    outbounds.Add(outbound);
                }

                node.LocalTestPort = port;
                testableNodes.Add(node);

                inbounds.Add(new JsonObject
                {
                    ["type"] = "mixed",
                    ["tag"] = inboundTag,
                    ["listen"] = "127.0.0.1",
                    ["listen_port"] = port
                });

                rules.Add(new JsonObject
                {
                    ["inbound"] = new JsonArray { inboundTag },
                    ["outbound"] = targetTag
                });
            }

            if (unusedPorts.Count > 0)
            {
                PortAllocator.ReleasePorts(unusedPorts);
            }

            if (testableNodes.Count == 0)
                return null;

            outbounds.Add(new JsonObject
            {
                ["type"] = "direct",
                ["tag"] = "direct"
            });

            var root = new JsonObject
            {
                ["log"] = new JsonObject { ["level"] = "fatal" },
                ["inbounds"] = inbounds,
                ["outbounds"] = outbounds,
                ["route"] = new JsonObject
                {
                    ["rules"] = rules,
                    ["final"] = "direct"
                }
            };

            if (endpoints.Count > 0)
            {
                root["endpoints"] = endpoints;
            }

            return root.ToJsonString();
        }

        private static JsonObject? BuildXrayOutbound(ProxyNode n, string tag)
        {
            if (string.IsNullOrWhiteSpace(n.Address) || n.Port <= 0 || n.Port > 65535)
                return null;

            switch (n.Protocol)
            {
                case ProxyProtocol.Vmess:
                {
                    if (!Guid.TryParse(n.Password, out _))
                        return null;
                    var stream = BuildXrayStreamSettings(n);
                    if (stream == null) return null;

                    var sec = ValidVmessSecurity.Contains(n.VmessSecurity) ? n.VmessSecurity : "auto";
                    return new JsonObject
                    {
                        ["tag"] = tag,
                        ["protocol"] = "vmess",
                        ["settings"] = new JsonObject
                        {
                            ["vnext"] = new JsonArray
                            {
                                new JsonObject
                                {
                                    ["address"] = n.Address,
                                    ["port"] = n.Port,
                                    ["users"] = new JsonArray
                                    {
                                        new JsonObject
                                        {
                                            ["id"] = n.Password,
                                            ["alterId"] = Math.Clamp(n.VmessAlterId, 0, 65535),
                                            ["security"] = sec
                                        }
                                    }
                                }
                            }
                        },
                        ["streamSettings"] = stream
                    };
                }

                case ProxyProtocol.Vless:
                {
                    if (!Guid.TryParse(n.Password, out _))
                        return null;

                    var encryption = string.IsNullOrWhiteSpace(n.VlessEncryption) ? "none" : n.VlessEncryption.Trim();
                    bool hasTransportSecurity = string.Equals(n.StreamSecurity, "tls", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(n.StreamSecurity, "reality", StringComparison.OrdinalIgnoreCase);

                    var stream = BuildXrayStreamSettings(n);
                    if (stream == null) return null;

                    var flow = ValidVlessFlows.Contains(n.Flow ?? string.Empty) ? (n.Flow ?? string.Empty) : string.Empty;
                    // XTLS Vision flow is only valid over TCP + TLS/Reality
                    if (!string.IsNullOrEmpty(flow) &&
                        (!string.Equals(n.Network, "tcp", StringComparison.OrdinalIgnoreCase) || !hasTransportSecurity))
                    {
                        flow = string.Empty;
                    }

                    return new JsonObject
                    {
                        ["tag"] = tag,
                        ["protocol"] = "vless",
                        ["settings"] = new JsonObject
                        {
                            ["vnext"] = new JsonArray
                            {
                                new JsonObject
                                {
                                    ["address"] = n.Address,
                                    ["port"] = n.Port,
                                    ["users"] = new JsonArray
                                    {
                                        new JsonObject
                                        {
                                            ["id"] = n.Password,
                                            ["encryption"] = encryption,
                                            ["flow"] = flow
                                        }
                                    }
                                }
                            }
                        },
                        ["streamSettings"] = stream
                    };
                }

                case ProxyProtocol.Trojan:
                {
                    if (string.IsNullOrWhiteSpace(n.Password))
                        return null;
                    var stream = BuildXrayStreamSettings(n);
                    if (stream == null) return null;

                    return new JsonObject
                    {
                        ["tag"] = tag,
                        ["protocol"] = "trojan",
                        ["settings"] = new JsonObject
                        {
                            ["servers"] = new JsonArray
                            {
                                new JsonObject
                                {
                                    ["address"] = n.Address,
                                    ["port"] = n.Port,
                                    ["password"] = n.Password
                                }
                            }
                        },
                        ["streamSettings"] = stream
                    };
                }

                case ProxyProtocol.Shadowsocks:
                {
                    if (string.IsNullOrWhiteSpace(n.SsMethod) || !ValidXraySsMethods.Contains(n.SsMethod))
                        return null;
                    if (string.IsNullOrWhiteSpace(n.Password))
                        return null;
                    if (n.SsMethod.StartsWith("2022-blake3-", StringComparison.OrdinalIgnoreCase) &&
                        !IsValidSs2022Password(n.SsMethod, n.Password))
                        return null;

                    return new JsonObject
                    {
                        ["tag"] = tag,
                        ["protocol"] = "shadowsocks",
                        ["settings"] = new JsonObject
                        {
                            ["servers"] = new JsonArray
                            {
                                new JsonObject
                                {
                                    ["address"] = n.Address,
                                    ["port"] = n.Port,
                                    ["method"] = n.SsMethod.ToLowerInvariant(),
                                    ["password"] = n.Password
                                }
                            }
                        }
                    };
                }

                case ProxyProtocol.Socks:
                    return BuildXraySocksOutbound(n, tag);

                default:
                    return null;
            }
        }

        private static JsonObject BuildXraySocksOutbound(ProxyNode n, string tag)
        {
            var server = new JsonObject
            {
                ["address"] = n.Address,
                ["port"] = n.Port
            };
            if (!string.IsNullOrEmpty(n.Username))
            {
                server["users"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["user"] = n.Username,
                        ["pass"] = n.Password
                    }
                };
            }

            return new JsonObject
            {
                ["tag"] = tag,
                ["protocol"] = "socks",
                ["settings"] = new JsonObject
                {
                    ["servers"] = new JsonArray { server }
                }
            };
        }

        private static JsonObject? BuildXrayStreamSettings(ProxyNode n)
        {
            var net = string.IsNullOrWhiteSpace(n.Network) ? "tcp" : n.Network.ToLowerInvariant();
            if (!ValidXrayNetworks.Contains(net))
                return null;

            var stream = new JsonObject
            {
                ["network"] = net
            };

            // Security
            if (string.Equals(n.StreamSecurity, "reality", StringComparison.OrdinalIgnoreCase))
            {
                if (!IsValidRealityPublicKey(n.PublicKey))
                    return null;

                var shortId = (n.ShortId ?? string.Empty).Trim();
                if (!IsValidRealityShortId(shortId))
                    return null;

                stream["security"] = "reality";
                stream["realitySettings"] = new JsonObject
                {
                    ["serverName"] = !string.IsNullOrEmpty(n.Sni) ? n.Sni : n.Address,
                    ["fingerprint"] = ValidFingerprints.Contains(n.Fingerprint) ? n.Fingerprint.ToLowerInvariant() : "chrome",
                    ["publicKey"] = n.PublicKey.Trim(),
                    ["shortId"] = shortId,
                    ["spiderX"] = string.IsNullOrEmpty(n.SpiderX) ? "/" : n.SpiderX
                };
            }
            else if (string.Equals(n.StreamSecurity, "tls", StringComparison.OrdinalIgnoreCase))
            {
                stream["security"] = "tls";
                var tls = new JsonObject
                {
                    ["serverName"] = !string.IsNullOrEmpty(n.Sni) ? n.Sni : (!string.IsNullOrEmpty(n.Host) ? n.Host : n.Address)
                };
                if (n.AllowInsecure)
                {
                    tls["allowInsecure"] = true;
                }
                if (!string.IsNullOrEmpty(n.Fingerprint) && ValidFingerprints.Contains(n.Fingerprint))
                {
                    tls["fingerprint"] = n.Fingerprint.ToLowerInvariant();
                }
                if (!string.IsNullOrEmpty(n.Alpn))
                {
                    var alpnArr = new JsonArray();
                    foreach (var a in n.Alpn.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                        alpnArr.Add(a);
                    if (alpnArr.Count > 0) tls["alpn"] = alpnArr;
                }
                stream["tlsSettings"] = tls;
            }
            else
            {
                stream["security"] = "none";
            }

            // Transport
            switch (net)
            {
                case "ws":
                {
                    var ws = new JsonObject
                    {
                        ["path"] = string.IsNullOrEmpty(n.Path) ? "/" : n.Path
                    };
                    if (!string.IsNullOrEmpty(n.Host))
                    {
                        ws["headers"] = new JsonObject { ["Host"] = n.Host };
                    }
                    stream["wsSettings"] = ws;
                    break;
                }
                case "httpupgrade":
                {
                    var hu = new JsonObject
                    {
                        ["path"] = string.IsNullOrEmpty(n.Path) ? "/" : n.Path
                    };
                    if (!string.IsNullOrEmpty(n.Host)) hu["host"] = n.Host;
                    stream["httpupgradeSettings"] = hu;
                    break;
                }
                case "xhttp":
                case "splithttp":
                {
                    var xh = new JsonObject
                    {
                        ["path"] = string.IsNullOrEmpty(n.Path) ? "/" : n.Path
                    };
                    if (!string.IsNullOrEmpty(n.Host)) xh["host"] = n.Host;
                    if (!string.IsNullOrEmpty(n.XhttpMode) && ValidXhttpModes.Contains(n.XhttpMode))
                        xh["mode"] = n.XhttpMode.ToLowerInvariant();
                    if (!string.IsNullOrWhiteSpace(n.XhttpExtra))
                    {
                        try
                        {
                            var extraNode = JsonNode.Parse(n.XhttpExtra);
                            if (extraNode != null) xh["extra"] = extraNode;
                        }
                        catch
                        {
                            // Ignore malformed extra JSON
                        }
                    }
                    stream[net == "xhttp" ? "xhttpSettings" : "splithttpSettings"] = xh;
                    break;
                }
                case "grpc":
                {
                    var grpc = new JsonObject
                    {
                        ["serviceName"] = n.GrpcServiceName ?? string.Empty,
                        ["multiMode"] = string.Equals(n.GrpcMode, "multi", StringComparison.OrdinalIgnoreCase)
                    };
                    if (!string.IsNullOrEmpty(n.GrpcAuthority)) grpc["authority"] = n.GrpcAuthority;
                    stream["grpcSettings"] = grpc;
                    break;
                }
                case "h2":
                {
                    var h2 = new JsonObject
                    {
                        ["path"] = string.IsNullOrEmpty(n.Path) ? "/" : n.Path
                    };
                    if (!string.IsNullOrEmpty(n.Host))
                    {
                        var hosts = new JsonArray();
                        foreach (var h in n.Host.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                            hosts.Add(h);
                        h2["host"] = hosts;
                    }
                    stream["httpSettings"] = h2;
                    break;
                }
                case "kcp":
                {
                    var validKcpHeaders = new[] { "none", "srtp", "utp", "wechat-video", "dtls", "wireguard" };
                    var hdr = validKcpHeaders.Contains(n.KcpHeaderType, StringComparer.OrdinalIgnoreCase)
                        ? n.KcpHeaderType.ToLowerInvariant()
                        : "none";
                    var kcp = new JsonObject
                    {
                        ["header"] = new JsonObject { ["type"] = hdr }
                    };
                    if (!string.IsNullOrEmpty(n.KcpSeed)) kcp["seed"] = n.KcpSeed;
                    stream["kcpSettings"] = kcp;
                    break;
                }
                case "tcp":
                {
                    if (string.Equals(n.RawHeaderType, "http", StringComparison.OrdinalIgnoreCase))
                    {
                        var req = new JsonObject
                        {
                            ["path"] = new JsonArray { string.IsNullOrEmpty(n.Path) ? "/" : n.Path }
                        };
                        if (!string.IsNullOrEmpty(n.Host))
                        {
                            req["headers"] = new JsonObject
                            {
                                ["Host"] = new JsonArray { n.Host }
                            };
                        }
                        stream["tcpSettings"] = new JsonObject
                        {
                            ["header"] = new JsonObject
                            {
                                ["type"] = "http",
                                ["request"] = req
                            }
                        };
                    }
                    break;
                }
            }

            return stream;
        }

        private static bool IsValidSs2022Password(string method, string password)
        {
            int expectedBytes = method.Contains("aes-128", StringComparison.OrdinalIgnoreCase) ? 16 : 32;
            var parts = password.Split(':', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0 || parts.Length > 2) return false;
            foreach (var p in parts)
            {
                try
                {
                    var raw = Convert.FromBase64String(p.Trim());
                    if (raw.Length != expectedBytes) return false;
                }
                catch
                {
                    return false;
                }
            }
            return true;
        }

        private static bool IsValidRealityPublicKey(string? pbk)
        {
            if (string.IsNullOrWhiteSpace(pbk)) return false;
            try
            {
                var s = pbk.Trim().Replace('-', '+').Replace('_', '/');
                int mod = s.Length % 4;
                if (mod > 0) s = s.PadRight(s.Length + (4 - mod), '=');
                return Convert.FromBase64String(s).Length == 32;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsValidRealityShortId(string sid)
        {
            if (sid.Length == 0) return true;
            if (sid.Length > 16 || sid.Length % 2 != 0) return false;
            foreach (var c in sid)
            {
                bool isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!isHex) return false;
            }
            return true;
        }

        private static JsonObject? BuildSingboxOutbound(ProxyNode n, string tag)
        {
            if (string.IsNullOrWhiteSpace(n.Address) || n.Port <= 0 || n.Port > 65535)
                return null;

            switch (n.Protocol)
            {
                case ProxyProtocol.Hysteria2:
                {
                    if (string.IsNullOrWhiteSpace(n.Password)) return null;
                    var obj = new JsonObject
                    {
                        ["type"] = "hysteria2",
                        ["tag"] = tag,
                        ["server"] = n.Address,
                        ["server_port"] = n.Port,
                        ["password"] = n.Password,
                        ["tls"] = BuildSingboxTls(n)
                    };
                    if (!string.IsNullOrEmpty(n.SalamanderPass))
                    {
                        obj["obfs"] = new JsonObject
                        {
                            ["type"] = "salamander",
                            ["password"] = n.SalamanderPass
                        };
                    }
                    return obj;
                }
                case ProxyProtocol.Tuic:
                {
                    if (!Guid.TryParse(n.Username, out _)) return null;
                    return new JsonObject
                    {
                        ["type"] = "tuic",
                        ["tag"] = tag,
                        ["server"] = n.Address,
                        ["server_port"] = n.Port,
                        ["uuid"] = n.Username,
                        ["password"] = n.Password,
                        ["congestion_control"] = string.IsNullOrEmpty(n.CongestionControl) ? "bbr" : n.CongestionControl,
                        ["tls"] = BuildSingboxTls(n)
                    };
                }
                default:
                    return null;
            }
        }

        /// <summary>
        /// Builds a sing-box 1.11+/1.12+ top-level WireGuard endpoint object.
        /// </summary>
        private static JsonObject? BuildSingboxWireGuardEndpoint(ProxyNode n, string tag)
        {
            if (string.IsNullOrWhiteSpace(n.Address) || n.Port <= 0 || n.Port > 65535)
                return null;
            if (string.IsNullOrWhiteSpace(n.Password) || string.IsNullOrWhiteSpace(n.PublicKey))
                return null;

            var addrs = new JsonArray();
            var rawAddrs = string.IsNullOrWhiteSpace(n.WgLocalAddress) ? "172.16.0.2/32" : n.WgLocalAddress;
            foreach (var a in rawAddrs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                addrs.Add(a.Contains('/') ? a : (a.Contains(':') ? $"{a}/128" : $"{a}/32"));
            }
            if (addrs.Count == 0) addrs.Add("172.16.0.2/32");

            var peer = new JsonObject
            {
                ["address"] = n.Address,
                ["port"] = n.Port,
                ["public_key"] = n.PublicKey.Trim(),
                ["allowed_ips"] = new JsonArray("0.0.0.0/0", "::/0")
            };

            var reserved = ParseWgReserved(n.WgReserved);
            if (reserved != null)
            {
                peer["reserved"] = new JsonArray(reserved[0], reserved[1], reserved[2]);
            }

            return new JsonObject
            {
                ["type"] = "wireguard",
                ["tag"] = tag,
                ["address"] = addrs,
                ["private_key"] = n.Password.Trim(),
                ["mtu"] = n.WgMtu > 0 ? n.WgMtu : 1280,
                ["peers"] = new JsonArray { peer }
            };
        }

        private static int[]? ParseWgReserved(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;
            var trimmed = raw.Trim();

            if (trimmed.Contains(','))
            {
                var nums = trimmed.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(s => int.TryParse(s, out var v) && v is >= 0 and <= 255 ? (int?)v : null)
                    .Where(v => v.HasValue)
                    .Select(v => v!.Value)
                    .ToArray();
                return nums.Length == 3 ? nums : null;
            }

            // Support Base64-encoded 3-byte reserved field
            try
            {
                var s = trimmed.Replace('-', '+').Replace('_', '/');
                int mod = s.Length % 4;
                if (mod > 0) s = s.PadRight(s.Length + (4 - mod), '=');
                var bytes = Convert.FromBase64String(s);
                if (bytes.Length == 3)
                    return new int[] { bytes[0], bytes[1], bytes[2] };
            }
            catch { }

            return null;
        }

        private static JsonObject BuildSingboxTls(ProxyNode n)
        {
            var tls = new JsonObject
            {
                ["enabled"] = true,
                ["server_name"] = !string.IsNullOrEmpty(n.Sni) ? n.Sni : n.Address,
                ["insecure"] = n.AllowInsecure
            };
            if (!string.IsNullOrEmpty(n.Alpn))
            {
                var arr = new JsonArray();
                foreach (var a in n.Alpn.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    arr.Add(a);
                if (arr.Count > 0) tls["alpn"] = arr;
            }
            return tls;
        }
    }
}
