using System;

namespace V2SubAuto.Models
{
    public enum ProxyProtocol
    {
        Vmess,
        Vless,
        Trojan,
        Shadowsocks,
        Hysteria2,
        Tuic,
        Socks,
        WireGuard
    }

    public enum CoreEngineType
    {
        Xray,
        SingBox
    }

    public sealed class ProxyNode
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string RawUri { get; set; } = string.Empty;
        public string SourceName { get; set; } = string.Empty;

        public ProxyProtocol Protocol { get; set; }
        public CoreEngineType CoreType => Protocol switch
        {
            ProxyProtocol.Hysteria2 or ProxyProtocol.Tuic or ProxyProtocol.WireGuard => CoreEngineType.SingBox,
            _ => CoreEngineType.Xray
        };

        // Core identity fields (used by V2RayN CompareProfileItem)
        public string Remarks { get; set; } = string.Empty;
        public string Address { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Password { get; set; } = string.Empty; // UUID for vmess/vless, password for trojan/ss/hy2/tuic
        public string Username { get; set; } = string.Empty; // socks username or tuic uuid

        // Protocol extras
        public string VlessEncryption { get; set; } = "none";
        public string SsMethod { get; set; } = string.Empty;
        public string SsPlugin { get; set; } = string.Empty;
        public string VmessSecurity { get; set; } = "auto";
        public int VmessAlterId { get; set; } = 0;
        public string Flow { get; set; } = string.Empty;
        public string SalamanderPass { get; set; } = string.Empty;
        public string CongestionControl { get; set; } = "bbr";

        // Transport extras
        public string Network { get; set; } = "tcp"; // tcp, ws, grpc, h2, httpupgrade, xhttp, splithttp, kcp
        public string RawHeaderType { get; set; } = string.Empty;
        public string Host { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        public string XhttpMode { get; set; } = string.Empty;
        public string XhttpExtra { get; set; } = string.Empty;
        public string GrpcAuthority { get; set; } = string.Empty;
        public string GrpcServiceName { get; set; } = string.Empty;
        public string GrpcMode { get; set; } = string.Empty;
        public string KcpHeaderType { get; set; } = string.Empty;
        public string KcpSeed { get; set; } = string.Empty;

        // TLS / Reality
        public string StreamSecurity { get; set; } = string.Empty; // "", "tls", "reality"
        public string Sni { get; set; } = string.Empty;
        public string Alpn { get; set; } = string.Empty;
        public string Fingerprint { get; set; } = string.Empty;
        public string PublicKey { get; set; } = string.Empty;
        public string ShortId { get; set; } = string.Empty;
        public string SpiderX { get; set; } = string.Empty;
        public bool AllowInsecure { get; set; } = false;

        // WireGuard extras
        public string WgReserved { get; set; } = string.Empty;
        public string WgLocalAddress { get; set; } = "172.16.0.2/32";
        public int WgMtu { get; set; } = 1280;

        // Runtime test state
        public int LocalTestPort { get; set; }
        public int TcpingMs { get; set; } = -1;
        public int RealDelayMs { get; set; } = -1;
        public double DownloadSpeedMBps { get; set; } = 0.0;

        // Display helpers for WPF DataGrid
        public string ProtocolLabel => Protocol.ToString().ToUpperInvariant();
        public string EndpointDisplay => $"{Address}:{Port}";
        public string TcpingDisplay => TcpingMs > 0 ? $"{TcpingMs} ms" : "-";
        public string RealDelayDisplay => RealDelayMs > 0 ? $"{RealDelayMs} ms" : "-";
        public string SpeedDisplay => DownloadSpeedMBps > 0 ? $"{DownloadSpeedMBps:0.0} MB/s" : "-";
    }
}
