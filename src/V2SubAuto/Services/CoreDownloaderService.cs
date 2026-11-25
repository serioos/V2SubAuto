using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace V2SubAuto.Services
{
    /// <summary>
    /// Downloads the latest official Windows x64 Xray-core and sing-box binaries from GitHub Releases
    /// if they are not already bundled in the bin/ directory.
    /// </summary>
    public static class CoreDownloaderService
    {
        public static async Task<(bool XrayOk, bool SingboxOk)> DownloadLatestCoresAsync(
            string xrayTargetPath,
            string singboxTargetPath,
            Action<string> log,
            CancellationToken ct)
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(3) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("V2SubAuto/1.0");

            var xrayTask = DownloadCoreAsync(
                http,
                "https://api.github.com/repos/XTLS/Xray-core/releases/latest",
                name => name.Equals("Xray-windows-64.zip", StringComparison.OrdinalIgnoreCase),
                "xray.exe",
                xrayTargetPath,
                log,
                ct);

            var singboxTask = DownloadCoreAsync(
                http,
                "https://api.github.com/repos/SagerNet/sing-box/releases/latest",
                name => name.EndsWith("-windows-amd64.zip", StringComparison.OrdinalIgnoreCase)
                    && !name.Contains("legacy", StringComparison.OrdinalIgnoreCase)
                    && !name.Contains("fips", StringComparison.OrdinalIgnoreCase),
                "sing-box.exe",
                singboxTargetPath,
                log,
                ct);

            await Task.WhenAll(xrayTask, singboxTask).ConfigureAwait(false);
            return (xrayTask.Result, singboxTask.Result);
        }

        private static async Task<bool> DownloadCoreAsync(
            HttpClient http,
            string releaseApiUrl,
            Func<string, bool> assetMatch,
            string exeFileName,
            string targetExePath,
            Action<string> log,
            CancellationToken ct)
        {
            string? tempZip = null;
            string? tempExe = null;
            try
            {
                if (string.IsNullOrWhiteSpace(targetExePath))
                {
                    log($"Target path for {exeFileName} is empty.");
                    return false;
                }

                log($"Checking latest release for {exeFileName}...");
                var json = await http.GetStringAsync(releaseApiUrl, ct).ConfigureAwait(false);
                using var doc = JsonDocument.Parse(json);

                string? downloadUrl = null;
                if (doc.RootElement.TryGetProperty("assets", out var assets))
                {
                    foreach (var asset in assets.EnumerateArray())
                    {
                        var name = asset.GetProperty("name").GetString() ?? string.Empty;
                        if (assetMatch(name))
                        {
                            downloadUrl = asset.GetProperty("browser_download_url").GetString();
                            break;
                        }
                    }
                }

                if (string.IsNullOrWhiteSpace(downloadUrl))
                {
                    log($"Could not find Windows x64 archive for {exeFileName}.");
                    return false;
                }

                log($"Downloading {downloadUrl}...");
                tempZip = Path.Combine(Path.GetTempPath(), $"v2subauto_{Guid.NewGuid():N}.zip");
                using (var resp = await http.GetAsync(downloadUrl, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false))
                {
                    resp.EnsureSuccessStatusCode();
                    await using var fs = File.Create(tempZip);
                    await resp.Content.CopyToAsync(fs, ct).ConfigureAwait(false);
                }

                var fullTargetPath = Path.GetFullPath(targetExePath);
                var targetDir = Path.GetDirectoryName(fullTargetPath);
                if (!string.IsNullOrWhiteSpace(targetDir))
                {
                    Directory.CreateDirectory(targetDir);
                }

                using var archive = ZipFile.OpenRead(tempZip);
                var entry = archive.Entries.FirstOrDefault(e =>
                    e.Name.Equals(exeFileName, StringComparison.OrdinalIgnoreCase));
                if (entry == null)
                {
                    log($"{exeFileName} was not found inside the downloaded archive.");
                    return false;
                }

                // Extract to a staging file in the same directory and atomically swap
                tempExe = fullTargetPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
                entry.ExtractToFile(tempExe, overwrite: true);
                File.Move(tempExe, fullTargetPath, overwrite: true);
                tempExe = null;

                log($"Installed {exeFileName} -> {fullTargetPath}");
                return true;
            }
            catch (Exception ex)
            {
                log($"Failed to download {exeFileName}: {ex.Message}");
                return false;
            }
            finally
            {
                if (tempExe != null)
                {
                    try { if (File.Exists(tempExe)) File.Delete(tempExe); } catch { }
                }
                if (tempZip != null)
                {
                    try { if (File.Exists(tempZip)) File.Delete(tempZip); } catch { }
                }
            }
        }
    }
}
