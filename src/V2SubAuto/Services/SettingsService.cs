using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using V2SubAuto.Models;

namespace V2SubAuto.Services
{
    public sealed class SettingsService
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true,
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter() },
            TypeInfoResolver = new DefaultJsonTypeInfoResolver()
        };

        private readonly object _saveLock = new();

        public string BaseDirectory { get; }
        public string DataDirectory { get; }
        public string SettingsPath { get; }
        public string LastSubBase64Path { get; }
        public string LastSubRawPath { get; }

        public SettingsService()
        {
            BaseDirectory = AppContext.BaseDirectory;
            DataDirectory = Path.Combine(BaseDirectory, "data");
            Directory.CreateDirectory(DataDirectory);
            SettingsPath = Path.Combine(DataDirectory, "settings.json");
            LastSubBase64Path = Path.Combine(DataDirectory, "last_sub_base64.txt");
            LastSubRawPath = Path.Combine(DataDirectory, "last_sub_raw.txt");
        }

        public AppSettings Load()
        {
            try
            {
                if (File.Exists(SettingsPath))
                {
                    var json = File.ReadAllText(SettingsPath);
                    var loaded = JsonSerializer.Deserialize<AppSettings>(json, JsonOptions);
                    if (loaded != null)
                    {
                        loaded.Subscriptions ??= new();
                        if (loaded.RefreshIntervalMinutes < 1) loaded.RefreshIntervalMinutes = 60;
                        if (loaded.TcpingBatchSize < 1) loaded.TcpingBatchSize = 1000;
                        if (loaded.TcpingTimeoutSeconds < 1) loaded.TcpingTimeoutSeconds = 4;
                        if (loaded.RealPingBatchSize < 1) loaded.RealPingBatchSize = 500;
                        if (loaded.RealPingTimeoutSeconds < 2) loaded.RealPingTimeoutSeconds = 4;
                        if (loaded.MixedConcurrencyCount < 1) loaded.MixedConcurrencyCount = 8;
                        if (loaded.SpeedTestTimeoutSeconds < 2) loaded.SpeedTestTimeoutSeconds = 8;
                        if (loaded.LocalServerPort < 1024 || loaded.LocalServerPort > 65535) loaded.LocalServerPort = 18080;
                        return loaded;
                    }
                }
            }
            catch
            {
                // Fall back to default settings if file is corrupted
            }

            var defaults = new AppSettings();
            Save(defaults);
            return defaults;
        }

        public void Save(AppSettings settings)
        {
            lock (_saveLock)
            {
                Directory.CreateDirectory(DataDirectory);
                var json = JsonSerializer.Serialize(settings, JsonOptions);
                WriteTextAtomic(SettingsPath, json);
            }
        }

        public string ResolvePath(string configuredPath)
        {
            if (string.IsNullOrWhiteSpace(configuredPath))
                return string.Empty;

            return Path.IsPathRooted(configuredPath)
                ? configuredPath
                : Path.GetFullPath(Path.Combine(BaseDirectory, configuredPath));
        }

        public void SaveLastSubscription(string rawContent, string base64Content)
        {
            try
            {
                lock (_saveLock)
                {
                    Directory.CreateDirectory(DataDirectory);
                    WriteTextAtomic(LastSubRawPath, rawContent);
                    WriteTextAtomic(LastSubBase64Path, base64Content);
                }
            }
            catch
            {
                // Non-fatal persistence error
            }
        }

        public (string Raw, string Base64) LoadLastSubscription()
        {
            try
            {
                var raw = File.Exists(LastSubRawPath) ? File.ReadAllText(LastSubRawPath) : string.Empty;
                var b64 = File.Exists(LastSubBase64Path) ? File.ReadAllText(LastSubBase64Path) : string.Empty;
                return (raw, b64);
            }
            catch
            {
                return (string.Empty, string.Empty);
            }
        }

        private static void WriteTextAtomic(string targetPath, string content)
        {
            var tempPath = targetPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                File.WriteAllText(tempPath, content);
                File.Move(tempPath, targetPath, overwrite: true);
            }
            finally
            {
                try
                {
                    if (File.Exists(tempPath))
                        File.Delete(tempPath);
                }
                catch { }
            }
        }
    }
}
