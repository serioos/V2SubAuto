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

            // V2RayN exempts Trojan from StreamSecurity comparison:
            // (o.ConfigType == EConfigType.Trojan || o.StreamSecurity == n.StreamSecurity)
            var streamSec = n.Protocol == ProxyProtocol.Trojan ? "trojan_exempt" : Norm(n.StreamSecurity);

            return string.Join("\u001F",
                (int)n.Protocol,
                Norm(n.Address),
                n.Port,
                Norm(n.Password),
                Norm(n.Username),
                Norm(n.VlessEncryption),
                Norm(n.SsMethod),
                Norm(n.VmessSecurity),
                Norm(n.Network),
                Norm(n.RawHeaderType),
                Norm(n.Host),
                Norm(n.Path),
                Norm(n.XhttpMode),
                Norm(n.XhttpExtra),
                Norm(n.GrpcAuthority),
                Norm(n.GrpcServiceName),
                Norm(n.GrpcMode),
                Norm(n.KcpHeaderType),
                Norm(n.KcpSeed),
                streamSec,
                Norm(n.Flow),
                Norm(n.SalamanderPass),
                Norm(n.Sni),
                Norm(n.Alpn),
                Norm(n.Fingerprint),
                Norm(n.PublicKey),
                Norm(n.ShortId));
        }
    }
}
