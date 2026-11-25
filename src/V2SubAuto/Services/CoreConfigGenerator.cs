using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
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

        private static readonly HashSet<string> ValidSingboxNetworks = new(StringComparer.OrdinalIgnoreCase)
        {
            "tcp", "ws", "grpc", "h2", "httpupgrade"
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

        private static readonly HashSet<string> ValidKcpHeaders = new(StringComparer.OrdinalIgnoreCase)
        {
            "none", "srtp", "utp", "wechat-video", "dtls", "wireguard"
        };

        /// <summary>
        /// Returns true if the server address is a loopback, private RFC1918, link-local, or local domain.
        /// Xray-core v26.7.11+ only permits unencrypted VLESS/Trojan to private addresses.
        /// </summary>
        public static bool IsPrivateAddress(string? address)
        {
            if (string.IsNullOrWhiteSpace(address)) return false;
            var host = address.Trim();

            if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                host.EndsWith(".local", StringComparison.OrdinalIgnoreCase) ||
                host.EndsWith(".lan", StringComparison.OrdinalIgnoreCase) ||
                host.EndsWith(".internal", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (IPAddress.TryParse(host, out var ip))
            {
                if (IPAddress.IsLoopback(ip)) return true;

                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    var b = ip.GetAddressBytes();
                    return b[0] == 10
                        || b[0] == 127
                        || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                        || (b[0] == 192 && b[1] == 168)
                        || (b[0] == 169 && b[1] == 254);
                }

                if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal) return true;
                    var b = ip.GetAddressBytes();
                    return (b[0] & 0xFE) == 0xFC; // fc00::/7 Unique Local
                }
            }

            return false;
        }

        /// <summary>
        /// Returns true if this is a public VLESS or Trojan node without TLS/Reality (or VLESS encryption),
        /// which Xray-core v26.7.11+ rejects on startup.
        /// </summary>
        public static bool IsUnencryptedVlessOrTrojan(ProxyNode n)
        {
            bool hasTransportSecurity = string.Equals(n.StreamSecurity, "tls", StringComparison.OrdinalIgnoreCase)
                || string.Equals(n.StreamSecurity, "reality", StringComparison.OrdinalIgnoreCase);

            if (hasTransportSecurity || IsPrivateAddress(n.Address))
                return false;

            if (n.Protocol == ProxyProtocol.Vless)
            {
                bool hasVlessEnc = !string.IsNullOrWhiteSpace(n.VlessEncryption)
                    && !string.Equals(n.VlessEncryption.Trim(), "none", StringComparison.OrdinalIgnoreCase);
                return !hasVlessEnc;
            }

            return n.Protocol == ProxyProtocol.Trojan;
        }

        /// <summary>
        /// Returns true if the node uses TLS with allowInsecure enabled (which Xray-core v26.2.6+ removed).
        /// </summary>
        public static bool IsInsecureTlsNode(ProxyNode n)
        {
            return string.Equals(n.StreamSecurity, "tls", StringComparison.OrdinalIgnoreCase) && n.AllowInsecure;
        }

        /// <summary>
        /// Returns true if sing-box natively supports this node's protocol and transport.
        /// </summary>
        public static bool CanRunInSingbox(ProxyNode n)
        {
            if (n.CoreType == CoreEngineType.SingBox)
                return true;

            if (n.Protocol is not (ProxyProtocol.Vless or ProxyProtocol.Vmess or ProxyProtocol.Trojan))
                return false;

            if (string.Equals(n.StreamSecurity, "reality", StringComparison.OrdinalIgnoreCase))
                return false;

            var net = string.IsNullOrWhiteSpace(n.Network) ? "tcp" : n.Network.ToLowerInvariant();
            if (!ValidSingboxNetworks.Contains(net))
                return false;

            if (net == "tcp" && string.Equals(n.RawHeaderType, "http", StringComparison.OrdinalIgnoreCase))
                return false;

            if (n.Protocol == ProxyProtocol.Vless)
            {
                bool hasVlessEnc = !string.IsNullOrWhiteSpace(n.VlessEncryption)
                    && !string.Equals(n.VlessEncryption.Trim(), "none", StringComparison.OrdinalIgnoreCase);
                if (hasVlessEnc) return false;
            }

            return true;
        }

        /// <summary>
        /// Selects which core engine should test a node. When AllowInsecureAndUnencrypted is enabled,
        /// unencrypted VLESS/Trojan and insecure TLS nodes on sing-box-compatible transports are routed
        /// to sing-box (which natively allows plaintext VLESS/Trojan and tls.insecure=true).
        /// </summary>
        public static CoreEngineType ResolveCoreEngine(ProxyNode n, bool allowInsecureAndUnencrypted)
        {
            if (n.CoreType == CoreEngineType.SingBox)
                return CoreEngineType.SingBox;

            if (allowInsecureAndUnencrypted &&
                (IsUnencryptedVlessOrTrojan(n) || IsInsecureTlsNode(n)) &&
                CanRunInSingbox(n))
            {
                return CoreEngineType.SingBox;
            }

            return CoreEngineType.Xray;
        }

        /// <summary>
        /// Zero-allocation structural validation used before Tcping so malformed (or disallowed unencrypted)
        /// nodes never waste sockets or crash core batches.
        /// </summary>
        public static bool IsStructurallyValid(ProxyNode n, bool allowInsecureAndUnencrypted = false)
        {
            if (string.IsNullOrWhiteSpace(n.Address) || n.Port <= 0 || n.Port > 65535)
                return false;

            if (!allowInsecureAndUnencrypted && IsUnencryptedVlessOrTrojan(n))
                return false;

            var engine = ResolveCoreEngine(n, allowInsecureAndUnencrypted);
            if (engine == CoreEngineType.Xray)
            {
                switch (n.Protocol)
                {
                    case ProxyProtocol.Vmess:
                    case ProxyProtocol.Vless:
                        if (!Guid.TryParse(n.Password, out _)) return false;
                        return IsValidXrayStream(n);

                    case ProxyProtocol.Trojan:
                        if (string.IsNullOrWhiteSpace(n.Password)) return false;
                        return IsValidXrayStream(n);

                    case ProxyProtocol.Shadowsocks:
                        if (string.IsNullOrWhiteSpace(n.SsMethod) || !ValidXraySsMethods.Contains(n.SsMethod))
                            return false;
                        if (string.IsNullOrWhiteSpace(n.Password))
                            return false;
                        if (n.SsMethod.StartsWith("2022-blake3-", StringComparison.OrdinalIgnoreCase) &&
                            !IsValidSs2022Password(n.SsMethod, n.Password))
                            return false;
                        return true;

                    case ProxyProtocol.Socks:
                        return true;

                    default:
                        return false;
                }
            }
            else
            {
                switch (n.Protocol)
                {
                    case ProxyProtocol.Hysteria2:
                        return !string.IsNullOrWhiteSpace(n.Password);

                    case ProxyProtocol.Trojan:
                        return !string.IsNullOrWhiteSpace(n.Password) && IsValidSingboxTransport(n);

                    case ProxyProtocol.Tuic:
                        return Guid.TryParse(n.Username, out _);

                    case ProxyProtocol.Vless:
                    case ProxyProtocol.Vmess:
                        return Guid.TryParse(n.Password, out _) && IsValidSingboxTransport(n);

                    case ProxyProtocol.WireGuard:
                        return IsValidWgKey(n.Password) && IsValidWgKey(n.PublicKey);

                    default:
                        return false;
                }
            }
        }

        private static bool IsValidUrlPath(string? path)
        {
            if (string.IsNullOrEmpty(path)) return true;
            for (int i = 0; i < path.Length; i++)
            {
                char c = path[i];
                if (c < 0x20 || c == 0x7F) return false;
                if (c == '%')
                {
                    if (i + 2 >= path.Length || !IsHexDigit(path[i + 1]) || !IsHexDigit(path[i + 2]))
                        return false;
                    i += 2;
                }
            }
            return true;
        }

        private static bool IsHexDigit(char c) =>
            (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');

        private static bool IsValidSingboxTransport(ProxyNode n)
        {
            var net = string.IsNullOrWhiteSpace(n.Network) ? "tcp" : n.Network.ToLowerInvariant();
            if (net is "ws" or "httpupgrade" or "h2")
                return IsValidUrlPath(n.Path);
            return true;
        }

        private static bool IsValidXrayStream(ProxyNode n)
        {
            var net = string.IsNullOrWhiteSpace(n.Network) ? "tcp" : n.Network;
            if (!ValidXrayNetworks.Contains(net))
                return false;

            if (net.Equals("ws", StringComparison.OrdinalIgnoreCase) ||
                net.Equals("httpupgrade", StringComparison.OrdinalIgnoreCase) ||
                net.Equals("h2", StringComparison.OrdinalIgnoreCase) ||
                net.Equals("xhttp", StringComparison.OrdinalIgnoreCase) ||
                net.Equals("splithttp", StringComparison.OrdinalIgnoreCase))
            {
                if (!IsValidUrlPath(n.Path))
                    return false;
            }

            if (string.Equals(n.StreamSecurity, "reality", StringComparison.OrdinalIgnoreCase))
            {
                if (!IsValidRealityPublicKey(n.PublicKey))
                    return false;
                var shortId = (n.ShortId ?? string.Empty).Trim();
                if (!IsValidRealityShortId(shortId))
                    return false;
            }

            return true;
        }

        public static string? GenerateXraySpeedtestConfig(
            IList<ProxyNode> nodes,
            bool allowInsecureAndUnencrypted,
            out List<ProxyNode> testableNodes,
            out List<int> leasedPorts,
            out bool portAllocationFailed)
        {
            testableNodes = new List<ProxyNode>();
            leasedPorts = new List<int>();
            portAllocationFailed = false;

            var ports = PortAllocator.AllocatePorts(nodes.Count);
            if (ports.Count < nodes.Count)
            {
                portAllocationFailed = true;
                return null;
            }

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

                bool needsLoopbackRelay = IsUnencryptedVlessOrTrojan(node);
                if (needsLoopbackRelay && !allowInsecureAndUnencrypted)
                {
                    unusedPorts.Add(port);
                    continue;
                }

                string? overrideAddr = null;
                int? overridePort = null;
                int relayPort = 0;

                if (needsLoopbackRelay)
                {
                    var relayAlloc = PortAllocator.AllocatePorts(1);
                    if (relayAlloc.Count == 0)
                    {
                        unusedPorts.Add(port);
                        portAllocationFailed = true;
                        continue;
                    }
                    relayPort = relayAlloc[0];
                    overrideAddr = "127.0.0.1";
                    overridePort = relayPort;
                }

                var outbound = BuildXrayOutbound(node, outboundTag, overrideAddr, overridePort);
                if (outbound == null)
                {
                    unusedPorts.Add(port);
                    if (relayPort > 0) unusedPorts.Add(relayPort);
                    continue;
                }

                node.LocalTestPort = port;
                testableNodes.Add(node);
                leasedPorts.Add(port);

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

                if (relayPort > 0)
                {
                    leasedPorts.Add(relayPort);
                    var relayTag = $"relay{port}";
                    inbounds.Add(new JsonObject
                    {
                        ["tag"] = relayTag,
                        ["listen"] = "127.0.0.1",
                        ["port"] = relayPort,
                        ["protocol"] = "dokodemo-door",
                        ["settings"] = new JsonObject
                        {
                            ["address"] = node.Address,
                            ["port"] = node.Port,
                            ["network"] = "tcp,udp"
                        }
                    });
                    rules.Add(new JsonObject
                    {
                        ["type"] = "field",
                        ["inboundTag"] = new JsonArray { relayTag },
                        ["outboundTag"] = "direct"
                    });
                }
            }

            if (unusedPorts.Count > 0)
            {
                PortAllocator.ReleasePorts(unusedPorts);
            }

            if (testableNodes.Count == 0)
            {
                PortAllocator.ReleasePorts(leasedPorts);
                leasedPorts.Clear();
                return null;
            }

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

        public static string? GenerateSingboxSpeedtestConfig(
            IList<ProxyNode> nodes,
            bool allowInsecureAndUnencrypted,
            out List<ProxyNode> testableNodes,
            out List<int> leasedPorts,
            out bool portAllocationFailed)
        {
            testableNodes = new List<ProxyNode>();
            leasedPorts = new List<int>();
            portAllocationFailed = false;

            var ports = PortAllocator.AllocatePorts(nodes.Count);
            if (ports.Count < nodes.Count)
            {
                portAllocationFailed = true;
                return null;
            }

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
                    var outbound = BuildSingboxOutbound(node, targetTag, allowInsecureAndUnencrypted);
                    if (outbound == null)
                    {
                        unusedPorts.Add(port);
                        continue;
                    }
                    outbounds.Add(outbound);
                }

                node.LocalTestPort = port;
                testableNodes.Add(node);
                leasedPorts.Add(port);

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
            {
                PortAllocator.ReleasePorts(leasedPorts);
                leasedPorts.Clear();
                return null;
            }

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

        private static JsonObject? BuildXrayOutbound(
            ProxyNode n,
            string tag,
            string? overrideAddress = null,
            int? overridePort = null)
        {
            if (string.IsNullOrWhiteSpace(n.Address) || n.Port <= 0 || n.Port > 65535)
                return null;

            var targetAddr = overrideAddress ?? n.Address;
            var targetPort = overridePort ?? n.Port;

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
                                    ["address"] = targetAddr,
                                    ["port"] = targetPort,
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
                                    ["address"] = targetAddr,
                                    ["port"] = targetPort,
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
                                    ["address"] = targetAddr,
                                    ["port"] = targetPort,
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
                                    ["address"] = targetAddr,
                                    ["port"] = targetPort,
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
            if (net is "ws" or "httpupgrade" or "h2" or "xhttp" or "splithttp" && !IsValidUrlPath(n.Path))
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
                // Note: Xray-core v26.2.6+ removed tlsSettings.allowInsecure and fails to start if present.
                // Insecure TLS nodes are routed to sing-box when AllowInsecureAndUnencrypted is enabled.
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
                    var hdr = ValidKcpHeaders.Contains(n.KcpHeaderType)
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

        private static bool IsValidWgKey(string? key)
        {
            if (string.IsNullOrWhiteSpace(key)) return false;
            try
            {
                var s = key.Trim().Replace('-', '+').Replace('_', '/');
                int mod = s.Length % 4;
                if (mod > 0) s = s.PadRight(s.Length + (4 - mod), '=');
                return Convert.FromBase64String(s).Length == 32;
            }
            catch
            {
                return false;
            }
        }

        private static bool TryNormalizeCidr(string candidate, out string normalized)
        {
            normalized = string.Empty;
            if (string.IsNullOrWhiteSpace(candidate)) return false;

            var slashIdx = candidate.IndexOf('/');
            if (slashIdx >= 0)
            {
                var ipPart = candidate[..slashIdx].Trim();
                var prefixPart = candidate[(slashIdx + 1)..].Trim();
                if (!IPAddress.TryParse(ipPart, out var ip) || !int.TryParse(prefixPart, out var prefix))
                    return false;

                int maxPrefix = ip.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
                if (prefix < 0 || prefix > maxPrefix)
                    return false;

                normalized = $"{ip}/{prefix}";
                return true;
            }

            if (!IPAddress.TryParse(candidate.Trim(), out var parsedIp))
                return false;

            normalized = parsedIp.AddressFamily == AddressFamily.InterNetworkV6
                ? $"{parsedIp}/128"
                : $"{parsedIp}/32";
            return true;
        }

        private static JsonObject? BuildSingboxOutbound(ProxyNode n, string tag, bool allowInsecureAndUnencrypted)
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
                        ["tls"] = BuildSingboxTls(n, allowInsecureAndUnencrypted, forceEnabled: true)
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
                        ["tls"] = BuildSingboxTls(n, allowInsecureAndUnencrypted, forceEnabled: true)
                    };
                }
                case ProxyProtocol.Vless:
                {
                    if (!Guid.TryParse(n.Password, out _)) return null;
                    if (!IsValidSingboxTransport(n)) return null;
                    var obj = new JsonObject
                    {
                        ["type"] = "vless",
                        ["tag"] = tag,
                        ["server"] = n.Address,
                        ["server_port"] = n.Port,
                        ["uuid"] = n.Password
                    };
                    bool hasTls = string.Equals(n.StreamSecurity, "tls", StringComparison.OrdinalIgnoreCase);
                    if (hasTls)
                    {
                        obj["tls"] = BuildSingboxTls(n, allowInsecureAndUnencrypted, forceEnabled: false);
                        // sing-box only supports xtls-rprx-vision (not xtls-rprx-vision-udp443)
                        if (string.Equals(n.Flow, "xtls-rprx-vision", StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(n.Network, "tcp", StringComparison.OrdinalIgnoreCase))
                        {
                            obj["flow"] = "xtls-rprx-vision";
                        }
                    }
                    var transport = BuildSingboxTransport(n);
                    if (transport != null) obj["transport"] = transport;
                    return obj;
                }
                case ProxyProtocol.Trojan:
                {
                    if (string.IsNullOrWhiteSpace(n.Password)) return null;
                    if (!IsValidSingboxTransport(n)) return null;
                    var obj = new JsonObject
                    {
                        ["type"] = "trojan",
                        ["tag"] = tag,
                        ["server"] = n.Address,
                        ["server_port"] = n.Port,
                        ["password"] = n.Password
                    };
                    if (string.Equals(n.StreamSecurity, "tls", StringComparison.OrdinalIgnoreCase))
                    {
                        obj["tls"] = BuildSingboxTls(n, allowInsecureAndUnencrypted, forceEnabled: false);
                    }
                    var transport = BuildSingboxTransport(n);
                    if (transport != null) obj["transport"] = transport;
                    return obj;
                }
                case ProxyProtocol.Vmess:
                {
                    if (!Guid.TryParse(n.Password, out _)) return null;
                    if (!IsValidSingboxTransport(n)) return null;
                    var sec = ValidVmessSecurity.Contains(n.VmessSecurity) ? n.VmessSecurity : "auto";
                    var obj = new JsonObject
                    {
                        ["type"] = "vmess",
                        ["tag"] = tag,
                        ["server"] = n.Address,
                        ["server_port"] = n.Port,
                        ["uuid"] = n.Password,
                        ["security"] = sec,
                        ["alter_id"] = Math.Clamp(n.VmessAlterId, 0, 65535)
                    };
                    if (string.Equals(n.StreamSecurity, "tls", StringComparison.OrdinalIgnoreCase))
                    {
                        obj["tls"] = BuildSingboxTls(n, allowInsecureAndUnencrypted, forceEnabled: false);
                    }
                    var transport = BuildSingboxTransport(n);
                    if (transport != null) obj["transport"] = transport;
                    return obj;
                }
                default:
                    return null;
            }
        }

        private static JsonObject? BuildSingboxTransport(ProxyNode n)
        {
            var net = string.IsNullOrWhiteSpace(n.Network) ? "tcp" : n.Network.ToLowerInvariant();
            switch (net)
            {
                case "ws":
                {
                    var ws = new JsonObject
                    {
                        ["type"] = "ws",
                        ["path"] = string.IsNullOrEmpty(n.Path) ? "/" : n.Path
                    };
                    if (!string.IsNullOrEmpty(n.Host))
                    {
                        ws["headers"] = new JsonObject { ["Host"] = n.Host };
                    }
                    return ws;
                }
                case "grpc":
                {
                    return new JsonObject
                    {
                        ["type"] = "grpc",
                        ["service_name"] = n.GrpcServiceName ?? string.Empty
                    };
                }
                case "httpupgrade":
                {
                    var hu = new JsonObject
                    {
                        ["type"] = "httpupgrade",
                        ["path"] = string.IsNullOrEmpty(n.Path) ? "/" : n.Path
                    };
                    if (!string.IsNullOrEmpty(n.Host)) hu["host"] = n.Host;
                    return hu;
                }
                case "h2":
                {
                    var h2 = new JsonObject
                    {
                        ["type"] = "http",
                        ["path"] = string.IsNullOrEmpty(n.Path) ? "/" : n.Path
                    };
                    if (!string.IsNullOrEmpty(n.Host))
                    {
                        var hosts = new JsonArray();
                        foreach (var h in n.Host.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                            hosts.Add(h);
                        if (hosts.Count > 0) h2["host"] = hosts;
                    }
                    return h2;
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
            if (!IsValidWgKey(n.Password) || !IsValidWgKey(n.PublicKey))
                return null;

            var addrs = new JsonArray();
            var rawAddrs = string.IsNullOrWhiteSpace(n.WgLocalAddress) ? "172.16.0.2/32" : n.WgLocalAddress;
            foreach (var a in rawAddrs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (TryNormalizeCidr(a, out var cidr))
                {
                    addrs.Add(cidr);
                }
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

        private static JsonObject BuildSingboxTls(ProxyNode n, bool allowInsecureAndUnencrypted, bool forceEnabled)
        {
            bool insecure = allowInsecureAndUnencrypted && n.AllowInsecure;
            var serverName = !string.IsNullOrEmpty(n.Sni)
                ? n.Sni
                : (!string.IsNullOrEmpty(n.Host) ? n.Host : n.Address);

            var tls = new JsonObject
            {
                ["enabled"] = true,
                ["server_name"] = serverName,
                ["insecure"] = insecure
            };
            if (!string.IsNullOrEmpty(n.Alpn))
            {
                var arr = new JsonArray();
                foreach (var a in n.Alpn.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    arr.Add(a);
                if (arr.Count > 0) tls["alpn"] = arr;
            }
            if (!forceEnabled && !string.IsNullOrEmpty(n.Fingerprint) && ValidFingerprints.Contains(n.Fingerprint))
            {
                tls["utls"] = new JsonObject
                {
                    ["enabled"] = true,
                    ["fingerprint"] = n.Fingerprint.ToLowerInvariant()
                };
            }
            return tls;
        }
    }
}
