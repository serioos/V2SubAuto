using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using V2SubAuto.Models;

namespace V2SubAuto.Services
{
    public sealed record SubscriptionImportResult(
        List<SubscriptionSource> Added,
        int DuplicateCount,
        int InvalidLineCount);

    public static class SubscriptionImportParser
    {
        private static readonly char[] Separators = { '|', '\t' };

        private static readonly Regex ListPrefixRegex = new(
            @"^(?:[-*•]\s+|\d+[.)]\s+)",
            RegexOptions.Compiled);

        public static SubscriptionImportResult ParseLines(
            IEnumerable<string> lines,
            IEnumerable<string> existingUrls,
            int startingIndex = 1)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var existing in existingUrls)
            {
                if (!string.IsNullOrWhiteSpace(existing))
                {
                    seen.Add(NormalizeUrlForDedup(existing));
                }
            }

            var added = new List<SubscriptionSource>();
            int duplicates = 0;
            int invalidLines = 0;
            int nextIndex = Math.Max(1, startingIndex);

            foreach (var rawLine in lines)
            {
                var trimmed = (rawLine ?? string.Empty).Trim();
                if (string.IsNullOrEmpty(trimmed))
                    continue;

                if (trimmed.StartsWith('#') || trimmed.StartsWith("//", StringComparison.Ordinal) || trimmed.StartsWith(';'))
                    continue;

                if (!TryExtractEntry(trimmed, out var customName, out var url, out var uri))
                {
                    invalidLines++;
                    continue;
                }

                var dedupKey = NormalizeUrlForDedup(url);
                if (!seen.Add(dedupKey))
                {
                    duplicates++;
                    continue;
                }

                var name = !string.IsNullOrWhiteSpace(customName)
                    ? customName
                    : DeriveNameFromUri(uri, nextIndex);

                added.Add(new SubscriptionSource
                {
                    Name = name,
                    Url = url,
                    Enabled = true
                });

                nextIndex++;
            }

            return new SubscriptionImportResult(added, duplicates, invalidLines);
        }

        private static bool TryExtractEntry(string line, out string customName, out string url, out Uri uri)
        {
            customName = string.Empty;
            url = string.Empty;
            uri = null!;

            // Strip markdown / numbered list prefix first (e.g. "- Name | https://..." or "1. https://...")
            var cleaned = ListPrefixRegex.Replace(line, string.Empty).Trim();
            if (string.IsNullOrEmpty(cleaned))
                return false;

            // Direct URL on the line
            if (TryParseHttpUrl(cleaned, out var directUri))
            {
                url = cleaned;
                uri = directUri;
                return true;
            }

            // Optional "Name | URL" or "Name<TAB>URL" format
            foreach (var separator in Separators)
            {
                int idx = cleaned.IndexOf(separator);
                if (idx > 0 && idx < cleaned.Length - 1)
                {
                    var left = cleaned.Substring(0, idx).Trim();
                    var right = cleaned.Substring(idx + 1).Trim();
                    if (TryParseHttpUrl(right, out var sepUri))
                    {
                        customName = left;
                        url = right;
                        uri = sepUri;
                        return true;
                    }
                }
            }

            return false;
        }

        public static bool TryParseHttpUrl(string? candidate, out Uri uri)
        {
            uri = null!;
            if (string.IsNullOrWhiteSpace(candidate))
                return false;

            var trimmed = candidate.Trim();
            if (trimmed.Any(char.IsWhiteSpace))
                return false;

            if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var parsed))
                return false;

            if (!string.Equals(parsed.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(parsed.Host))
                return false;

            uri = parsed;
            return true;
        }

        public static string NormalizeUrlForDedup(string url)
        {
            var trimmed = url.Trim();
            if (TryParseHttpUrl(trimmed, out var uri))
            {
                var portPart = uri.IsDefaultPort ? string.Empty : ":" + uri.Port;
                return $"{uri.Scheme.ToLowerInvariant()}://{uri.Host.ToLowerInvariant()}{portPart}{uri.PathAndQuery}{uri.Fragment}";
            }

            return trimmed;
        }

        private static string DeriveNameFromUri(Uri uri, int fallbackIndex)
        {
            const int MaxNameLength = 48;
            var host = uri.Host;
            var segments = uri.AbsolutePath
                .Split('/', StringSplitOptions.RemoveEmptyEntries)
                .Select(s => { try { return Uri.UnescapeDataString(s); } catch { return s; } })
                .ToArray();

            string candidate;
            if (string.Equals(host, "raw.githubusercontent.com", StringComparison.OrdinalIgnoreCase) && segments.Length >= 2)
            {
                var repo = $"{segments[0]}/{segments[1]}";
                var file = segments.Length >= 4 ? segments[^1] : string.Empty;
                candidate = !string.IsNullOrWhiteSpace(file) ? $"{repo} ({file})" : repo;
            }
            else if (segments.Length > 0)
            {
                var last = segments[^1];
                candidate = !string.IsNullOrWhiteSpace(last) ? $"{host}/{last}" : host;
            }
            else
            {
                candidate = host;
            }

            candidate = candidate.Trim();
            if (string.IsNullOrEmpty(candidate))
                return $"Subscription {fallbackIndex}";

            if (candidate.Length > MaxNameLength)
                candidate = candidate.Substring(0, MaxNameLength - 1).TrimEnd() + "…";

            return candidate;
        }
    }
}
