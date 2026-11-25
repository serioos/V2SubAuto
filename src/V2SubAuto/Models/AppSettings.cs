using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;

namespace V2SubAuto.Models
{
    public sealed class SubscriptionSource : INotifyPropertyChanged
    {
        private string _name = "Default Subscription";
        private string _url = string.Empty;
        private bool _enabled = true;

        public string Name
        {
            get => _name;
            set
            {
                var next = value ?? string.Empty;
                if (_name != next)
                {
                    _name = next;
                    OnPropertyChanged();
                }
            }
        }

        public string Url
        {
            get => _url;
            set
            {
                var next = value ?? string.Empty;
                if (_url != next)
                {
                    _url = next;
                    OnPropertyChanged();
                }
            }
        }

        public bool Enabled
        {
            get => _enabled;
            set
            {
                if (_enabled != value)
                {
                    _enabled = value;
                    OnPropertyChanged();
                }
            }
        }

        public SubscriptionSource Clone() => new()
        {
            Name = _name,
            Url = _url,
            Enabled = _enabled
        };

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    public enum SortOrderMode
    {
        SpeedDescending,
        DelayAscending
    }

    public sealed class AppSettings
    {
        public const int MaxRealPingBatchSize = 250;

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

        // Security / Compatibility
        public bool AllowInsecureAndUnencrypted { get; set; } = false;

        // Tcping & Real Delay (tuned for fast batch throughput)
        public int TcpingBatchSize { get; set; } = 1000;
        public int TcpingTimeoutSeconds { get; set; } = 4;
        public int RealPingBatchSize { get; set; } = 250;
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
        public bool AllowLanAccess { get; set; } = true;
        public bool AppendMetricsToRemarks { get; set; } = true;
        public SortOrderMode OutputSortMode { get; set; } = SortOrderMode.SpeedDescending;
        public int MaxOutputConfigs { get; set; } = 0; // 0 = unlimited

        // Core Paths (relative to app directory or absolute)
        public string XrayExecutablePath { get; set; } = @"bin\xray\xray.exe";
        public string SingboxExecutablePath { get; set; } = @"bin\sing_box\sing-box.exe";

        public AppSettings Clone() => new()
        {
            AutoStartWithWindows = AutoStartWithWindows,
            StartMinimizedToTray = StartMinimizedToTray,
            RunImmediatelyOnStartup = RunImmediatelyOnStartup,
            AutoScheduleEnabled = AutoScheduleEnabled,
            RefreshIntervalMinutes = RefreshIntervalMinutes,
            Subscriptions = (Subscriptions ?? new List<SubscriptionSource>()).Select(s => s.Clone()).ToList(),
            EnableDeduplication = EnableDeduplication,
            EnableTcpingTest = EnableTcpingTest,
            EnableRealDelayTest = EnableRealDelayTest,
            EnableSpeedTest = EnableSpeedTest,
            KeepOlderDedupl = KeepOlderDedupl,
            AllowInsecureAndUnencrypted = AllowInsecureAndUnencrypted,
            TcpingBatchSize = TcpingBatchSize,
            TcpingTimeoutSeconds = TcpingTimeoutSeconds,
            RealPingBatchSize = RealPingBatchSize,
            RealPingTimeoutSeconds = RealPingTimeoutSeconds,
            BatchDelayIntervalSeconds = BatchDelayIntervalSeconds,
            RealPingTestUrl = RealPingTestUrl,
            MixedConcurrencyCount = MixedConcurrencyCount,
            SpeedTestUrl = SpeedTestUrl,
            SpeedTestTimeoutSeconds = SpeedTestTimeoutSeconds,
            MinDownloadSpeedMBps = MinDownloadSpeedMBps,
            LocalServerPort = LocalServerPort,
            AllowLanAccess = AllowLanAccess,
            AppendMetricsToRemarks = AppendMetricsToRemarks,
            OutputSortMode = OutputSortMode,
            MaxOutputConfigs = MaxOutputConfigs,
            XrayExecutablePath = XrayExecutablePath,
            SingboxExecutablePath = SingboxExecutablePath
        };

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
