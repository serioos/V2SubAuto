using System;
using System.Collections.Generic;

namespace V2SubAuto.Models
{
    public sealed class SubscriptionSource
    {
        public string Name { get; set; } = "Default Subscription";
        public string Url { get; set; } = string.Empty;
        public bool Enabled { get; set; } = true;
    }

    public enum SortOrderMode
    {
        SpeedDescending,
        DelayAscending
    }

    public sealed class AppSettings
    {
        // Startup & Tray
        public bool AutoStartWithWindows { get; set; } = true;
        public bool StartMinimizedToTray { get; set; } = true;
        public bool RunImmediatelyOnStartup { get; set; } = true;
        public bool AutoScheduleEnabled { get; set; } = true;

        // Schedule
        public int RefreshIntervalMinutes { get; set; } = 60;

        // Subscriptions
        public List<SubscriptionSource> Subscriptions { get; set; } = new()
        {
            new SubscriptionSource
            {
                Name = "0xRadikal Free V2Ray",
                Url = "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs_base64.txt",
                Enabled = true
            }
        };

        // Pipeline Steps (uncheck any step to skip it and pass remaining configs forward)
        public bool EnableDeduplication { get; set; } = true;
        public bool EnableTcpingTest { get; set; } = true;
        public bool EnableRealDelayTest { get; set; } = true;
        public bool EnableSpeedTest { get; set; } = true;

        // Deduplication (matches V2RayN KeepOlderDedupl)
        public bool KeepOlderDedupl { get; set; } = false;

        // Tcping & Real Delay (tuned for fast batch throughput)
        public int TcpingBatchSize { get; set; } = 1000;
        public int TcpingTimeoutSeconds { get; set; } = 4;
        public int RealPingBatchSize { get; set; } = 500;
        public int RealPingTimeoutSeconds { get; set; } = 4;
        public int BatchDelayIntervalSeconds { get; set; } = 0;
        public string RealPingTestUrl { get; set; } = "https://www.google.com/generate_204";

        // Mixed Test (Latency + Download Speed)
        public int MixedConcurrencyCount { get; set; } = 8;
        public string SpeedTestUrl { get; set; } = "https://cachefly.cachefly.net/50mb.test";
        public int SpeedTestTimeoutSeconds { get; set; } = 8;
        public double MinDownloadSpeedMBps { get; set; } = 1.0;

        // Local Subscription Server
        public int LocalServerPort { get; set; } = 18080;
        public bool AppendMetricsToRemarks { get; set; } = true;
        public SortOrderMode OutputSortMode { get; set; } = SortOrderMode.SpeedDescending;
        public int MaxOutputConfigs { get; set; } = 0; // 0 = unlimited

        // Core Paths (relative to app directory or absolute)
        public string XrayExecutablePath { get; set; } = @"bin\xray\xray.exe";
        public string SingboxExecutablePath { get; set; } = @"bin\sing_box\sing-box.exe";

        public static readonly string[] PresetPingUrls =
        {
            "https://www.google.com/generate_204",
            "https://www.youtube.com/generate_204",
            "https://www.gstatic.com/generate_204",
            "https://www.apple.com/library/test/success.html",
            "http://www.msftconnecttest.com/connecttest.txt"
        };

        public static readonly string[] PresetSpeedTestUrls =
        {
            "https://cachefly.cachefly.net/50mb.test",
            "https://cachefly.cachefly.net/10mb.test",
            "https://speed.cloudflare.com/__down?bytes=25000000",
            "https://speed.cloudflare.com/__down?bytes=50000000",
            "https://ash-speed.hetzner.com/100MB.bin",
            "https://proof.ovh.net/files/10Mb.dat"
        };
    }
}
