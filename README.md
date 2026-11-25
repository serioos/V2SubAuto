# V2SubAuto

Lightweight, zero-dependency Windows 11 (.NET 8 WPF) system-tray app that automates the exact [v2rayN](https://github.com/2dust/v2rayN) subscription, deduplication, Tcping, Real Delay, Mixed Speedtest, and filtering pipeline, then serves the surviving fast configs on a local HTTP subscription URL.

## Automated Pipeline (Exact v2rayN Parity)

1. **Windows 11 Auto-Start & Tray**: Registers under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (matching [AutoStartupHandler.cs](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Handler/AutoStartupHandler.cs)), starts minimized in the system tray on login, and immediately kicks off a pipeline run.
2. **Multi-URL Subscription Fetch**: Periodically downloads and decodes Base64 or plain-text config lists (`vmess`, `vless`, `trojan`, `ss`, `hysteria2`/`hy2`, `tuic`, `socks`, `wireguard`).
3. **Remove Duplicates**: Compares the exact same protocol, endpoint, credential, transport, and TLS/Reality fields as v2rayN's [`DedupServerList` / `CompareProfileItem`](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Handler/Data/ConfigDbHandler.cs) in O(N) time, honoring `KeepOlderDedupl`.
4. **Test Tcping + Remove Invalids**: Batched parallel TCP socket connects with 5-second timeout (matching [`RunTcpingAsync` / `GetTcpingTime`](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Services/SpeedtestService.cs)), removing all configs where `Delay == -1`.
5. **Test Real Delay + Remove Invalids**: Splits configs by core (`xray.exe` vs `sing-box.exe`), generates multi-inbound batch configs with automatic batch-size halving on failure, and runs 2× HTTP GET against `SpeedPingTestUrl` (default `https://www.google.com/generate_204`) via local SOCKS5 ports (matching [`GetRealPingTime`](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Handler/ConnectionHandler.cs)), removing all invalid configs.
6. **Test Latency & Download Speed + Filter**: Runs concurrent per-node Mixedtest (`MixedConcurrencyCount`), verifying Real Delay and measuring peak download speed in **MB/s** (`maxSpeed / 1_000_000`, matching [`DownloadDataAsync4Speed`](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Helper/DownloaderHelper.cs)), then drops invalids and configs below your minimum MB/s threshold.
7. **Local Subscription Server**: Serves surviving configs at `http://127.0.0.1:18080/sub` (Base64 for v2rayN), `/raw` (plain text), and `/status` (JSON), and caches the last good list on disk for instant availability after reboot.

## Building with GitHub Actions

1. Create a new GitHub repository and push the contents of this folder to `main`.
2. Open the **Actions** tab and wait for **Build Windows x64 Portable Release** to finish.
3. Download the **`V2SubAuto-win-x64`** artifact ZIP — it already includes the self-contained `V2SubAuto.exe` along with the latest official `xray.exe` and `sing-box.exe` binaries in `bin/`.
4. Extract anywhere on Windows 11 and run `V2SubAuto.exe`.

*(Tip: Pushing a version tag like `git tag v1.0.0 && git push origin v1.0.0` automatically publishes a GitHub Release with the ZIP attached.)*

## Building Locally (Windows 11)

Requires the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0):

```powershell
dotnet publish src/V2SubAuto/V2SubAuto.csproj -c Release -r win-x64 --self-contained true -o publish/V2SubAuto
```

Launch `publish/V2SubAuto/V2SubAuto.exe`, open **Settings**, and click **Download / Update Latest Xray & sing-box** to install the cores automatically.

## Adding to v2rayN

1. In v2rayN, open **Subscription group → Subscription group settings → Add**.
2. Set **Remarks** to `V2SubAuto` and **URL** to:
   ```
   http://127.0.0.1:18080/sub
   ```
3. Click **Confirm**, then click **Update subscription (without proxy)** whenever you want to pull the latest filtered configs.
