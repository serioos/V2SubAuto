using System;
using System.Net;
using System.Net.Http;

namespace V2SubAuto.Services
{
    /// <summary>
    /// Applies the "download through system proxy / VPN" setting to outbound HTTP traffic that fetches
    /// subscription lists and core binaries (never to the local test proxies used by the speed tests).
    /// </summary>
    public static class DownloadProxyHelper
    {
        /// <summary>
        /// ON  : route through the Windows system proxy (Internet Options / "Proxy" settings, PAC and
        ///       auto-detect included). A full-tunnel VPN / TUN adapter needs no proxy and works either way.
        /// OFF : always connect directly and ignore any system proxy.
        /// </summary>
        public static void Configure(SocketsHttpHandler handler, bool useSystemProxy)
        {
            if (useSystemProxy)
            {
                handler.UseProxy = true;
                handler.Proxy = HttpClient.DefaultProxy;
                handler.DefaultProxyCredentials = CredentialCache.DefaultCredentials;
            }
            else
            {
                handler.UseProxy = false;
                handler.Proxy = null;
            }
        }

        /// <summary>Human-readable description of the route a URL will take, for the log.</summary>
        public static string Describe(bool useSystemProxy, string? sampleUrl)
        {
            if (!useSystemProxy)
                return "direct connection (system proxy ignored)";

            try
            {
                if (!Uri.TryCreate(sampleUrl, UriKind.Absolute, out var uri))
                    return "system proxy";

                var proxy = HttpClient.DefaultProxy;
                if (proxy.IsBypassed(uri))
                    return "system proxy is enabled but bypassed for this address; connecting directly";

                var target = proxy.GetProxy(uri);
                if (target == null || target == uri)
                    return "no system proxy detected; connecting normally (an active full-tunnel VPN is used automatically)";

                return $"system proxy {target.Host}:{target.Port}";
            }
            catch
            {
                return "system proxy";
            }
        }
    }
}
