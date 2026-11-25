using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace V2SubAuto.Services
{
    /// <summary>
    /// Registers or removes Windows 11 login auto-startup via HKCU\...\Run,
    /// matching V2RayN's AutoStartupHandler approach with per-path unique key.
    /// </summary>
    public static class AutoStartupService
    {
        private const string RunRegistryPath = @"Software\Microsoft\Windows\CurrentVersion\Run";

        public static string GetRegistryValueName()
        {
            var baseDir = AppContext.BaseDirectory.TrimEnd('\\', '/').ToLowerInvariant();
            var hash = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(baseDir)))[..8];
            return $"V2SubAuto_{hash}";
        }

        public static string GetExecutablePath()
        {
            return Environment.ProcessPath
                ?? Process.GetCurrentProcess().MainModule?.FileName
                ?? Path.Combine(AppContext.BaseDirectory, "V2SubAuto.exe");
        }

        public static bool Apply(bool enable)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RunRegistryPath, writable: true);
                if (key == null) return false;

                var name = GetRegistryValueName();
                if (enable)
                {
                    var exePath = GetExecutablePath();
                    key.SetValue(name, $"\"{exePath}\" --autostart", RegistryValueKind.String);
                }
                else
                {
                    key.DeleteValue(name, throwOnMissingValue: false);
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static bool IsEnabled()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RunRegistryPath, writable: false);
                if (key == null) return false;
                var val = key.GetValue(GetRegistryValueName()) as string;
                return !string.IsNullOrWhiteSpace(val);
            }
            catch
            {
                return false;
            }
        }
    }
}
