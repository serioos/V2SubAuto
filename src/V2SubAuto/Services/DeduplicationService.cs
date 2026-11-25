using System;
using System.Collections.Generic;
using V2SubAuto.Models;

namespace V2SubAuto.Services
{
    /// <summary>
    /// Exact port of V2RayN's ConfigDbHandler.DedupServerList & CompareProfileItem,
    /// using an O(N) hash key over the exact same compared fields for speed on 10,000+ configs.
    /// </summary>
    public static class DeduplicationService
    {
        public static List<ProxyNode> RemoveDuplicates(IReadOnlyList<ProxyNode> nodes, bool keepOlderDedupl)
        {
            if (nodes.Count <= 1)
                return new List<ProxyNode>(nodes);

            var working = new List<ProxyNode>(nodes);
            if (!keepOlderDedupl)
            {
                working.Reverse();
            }

            var seen = new HashSet<string>(StringComparer.Ordinal);
            var kept = new List<ProxyNode>(working.Count);

            foreach (var item in working)
            {
                var key = BuildComparisonKey(item);
                if (seen.Add(key))
                {
                    kept.Add(item);
                }
            }

            if (!keepOlderDedupl)
            {
                kept.Reverse();
            }

            return kept;
        }

        /// <summary>
        /// Mirrors V2RayN CompareProfileItem(o, n, remarks: false):
        /// compares protocol, address, port, credentials, encryption/method, transport, and TLS/Reality fields.
        /// </summary>
        private static string BuildComparisonKey(ProxyNode n)
        {
            static string Norm(string? s) => string.IsNullOrEmpty(s) ? string.Empty : s;
            static string NormLower(string? s) => string.IsNullOrEmpty(s) ? string.Empty : s.Trim().ToLowerInvariant();

            // V2RayN exempts Trojan from StreamSecurity comparison:
            // (o.ConfigType == EConfigType.Trojan || o.StreamSecurity == n.StreamSecurity)
            var streamSec = n.Protocol == ProxyProtocol.Trojan ? "trojan_exempt" : NormLower(n.StreamSecurity);

            return string.Join("\u001F",
                (int)n.Protocol,
                NormLower(n.Address),
                n.Port,
                Norm(n.Password),
                Norm(n.Username),
                NormLower(n.VlessEncryption),
                NormLower(n.SsMethod),
                Norm(n.SsPlugin),
                NormLower(n.VmessSecurity),
                n.VmessAlterId,
                NormLower(n.Network),
                NormLower(n.RawHeaderType),
                NormLower(n.Host),
                Norm(n.Path),
                NormLower(n.XhttpMode),
                Norm(n.XhttpExtra),
                NormLower(n.GrpcAuthority),
                Norm(n.GrpcServiceName),
                NormLower(n.GrpcMode),
                NormLower(n.KcpHeaderType),
                Norm(n.KcpSeed),
                streamSec,
                NormLower(n.Flow),
                Norm(n.SalamanderPass),
                NormLower(n.CongestionControl),
                NormLower(n.Sni),
                NormLower(n.Alpn),
                NormLower(n.Fingerprint),
                Norm(n.PublicKey),
                Norm(n.ShortId),
                Norm(n.SpiderX),
                Norm(n.WgLocalAddress),
                Norm(n.WgReserved),
                n.WgMtu);
        }
    }
}
