using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using V2SubAuto.Models;
using V2SubAuto.Services;
using V2SubAuto.Views;

namespace V2SubAuto
{
    public partial class App : Application
    {
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyIcon(IntPtr hIcon);

        private Mutex? _singleInstanceMutex;
        private System.Windows.Forms.NotifyIcon? _trayIcon;
        private System.Windows.Forms.ContextMenuStrip? _trayMenu;
        private Font? _trayOpenFont;
        private Icon? _generatedIcon;

        private SettingsService _settingsService = null!;
        private AppSettings _settings = null!;
        private CoreProcessRunner _coreRunner = null!;
        private SpeedtestEngine _speedtestEngine = null!;
        private LocalSubscriptionServer _localServer = null!;
        private PipelineOrchestrator _orchestrator = null!;
        private MainWindow _mainWindow = null!;

        private bool _isExiting;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            DispatcherUnhandledException += OnDispatcherUnhandledException;
            AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
            TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;

            // Per-path mutex aligns with AutoStartupService's per-path portable registration
            var mutexName = $"V2SubAuto_SingleInstance_{AutoStartupService.GetRegistryValueName()}";
            _singleInstanceMutex = new Mutex(true, mutexName, out bool createdNew);
            if (!createdNew)
            {
                _singleInstanceMutex.Dispose();
                _singleInstanceMutex = null;
                MessageBox.Show(
                    "V2SubAuto is already running in the system tray.",
                    "V2SubAuto",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                Shutdown();
                return;
            }

            bool isAutoStartArg = e.Args.Any(a =>
                a.Equals("--autostart", StringComparison.OrdinalIgnoreCase) ||
                a.Equals("--minimized", StringComparison.OrdinalIgnoreCase));

            _settingsService = new SettingsService();
            _settings = _settingsService.Load();

            // Sync Windows 11 auto-startup registry entry with settings
            bool autoStartApplied = AutoStartupService.Apply(_settings.AutoStartWithWindows);

            _coreRunner = new CoreProcessRunner(_settingsService.BaseDirectory);
            _speedtestEngine = new SpeedtestEngine(_coreRunner, _settingsService);
            _localServer = new LocalSubscriptionServer();

            // Pre-load last good subscription so V2RayN can fetch immediately after boot
            int cachedCount = 0;
            DateTime? cachedTimestamp = null;
            var (cachedRaw, cachedB64) = _settingsService.LoadLastSubscription();
            if (!string.IsNullOrWhiteSpace(cachedB64))
            {
                cachedCount = cachedRaw.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length;
                cachedTimestamp = File.Exists(_settingsService.LastSubBase64Path)
                    ? File.GetLastWriteTimeUtc(_settingsService.LastSubBase64Path)
                    : DateTime.UtcNow;
                _localServer.UpdatePayload(cachedRaw, cachedB64, cachedCount, cachedTimestamp.Value);
            }

            bool serverStarted = _localServer.Start(_settings.LocalServerPort, _settings.AllowLanAccess);

            _orchestrator = new PipelineOrchestrator(
                _settings,
                _settingsService,
                _speedtestEngine,
                _localServer,
                _coreRunner);

            if (cachedCount > 0)
            {
                _orchestrator.InitializeCachedState(cachedCount, cachedTimestamp);
            }

            _mainWindow = new MainWindow(
                _settings,
                _settingsService,
                _localServer,
                _orchestrator,
                RequestExit);

            SetupTrayIcon(cachedCount);

            if (!autoStartApplied)
            {
                _mainWindow.LogWarning("Could not update Windows auto-startup registry entry.");
            }

            if (!serverStarted)
            {
                var msg = $"Subscription server could not bind to port {_settings.LocalServerPort}. Change the port in Settings and save.";
                _mainWindow.LogWarning(msg);
                _trayIcon?.ShowBalloonTip(4000, "V2SubAuto — Port Bind Error", msg, System.Windows.Forms.ToolTipIcon.Warning);
            }

            _orchestrator.OnSnapshotChanged += snapshot =>
            {
                Dispatcher.BeginInvoke(() =>
                {
                    if (_trayIcon != null)
                    {
                        var tip = snapshot.IsRunning
                            ? $"V2SubAuto: {snapshot.CurrentStage}"
                            : $"V2SubAuto: Serving {snapshot.FinalSurvivingCount} configs";
                        _trayIcon.Text = tip.Length > 63 ? tip[..63] : tip;
                    }
                });
            };

            // Show window unless started via Windows boot or configured to start minimized
            if (!isAutoStartArg && !_settings.StartMinimizedToTray)
            {
                ShowMainWindow();
            }

            // Start periodic schedule and immediately run pipeline on startup if enabled
            _orchestrator.StartScheduler();
            if (_settings.RunImmediatelyOnStartup)
            {
                _ = Task.Run(() => _orchestrator.RunPipelineAsync());
            }
        }

        private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            if (_isExiting)
                return;

            try
            {
                _mainWindow?.LogWarning($"Unexpected UI error: {e.Exception.Message}");
            }
            catch { }

            // Allow fatal runtime exceptions to terminate rather than leaving the app in a corrupted state
            if (e.Exception is OutOfMemoryException or StackOverflowException or AccessViolationException)
                return;

            e.Handled = true;
        }

        private void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            if (_isExiting) return;
            try
            {
                var msg = e.ExceptionObject is Exception ex ? ex.Message : e.ExceptionObject?.ToString() ?? "Unknown error";
                _mainWindow?.LogWarning($"Unhandled background error: {msg}");
            }
            catch { }
        }

        private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
        {
            if (_isExiting) return;
            try
            {
                _mainWindow?.LogWarning($"Unobserved task error: {e.Exception.GetBaseException().Message}");
            }
            catch { }
            e.SetObserved();
        }

        private void SetupTrayIcon(int initialServingCount)
        {
            _generatedIcon = CreateTrayIcon();
            _trayMenu = new System.Windows.Forms.ContextMenuStrip();

            var openItem = new System.Windows.Forms.ToolStripMenuItem("Open Dashboard");
            _trayOpenFont = new Font(openItem.Font, System.Drawing.FontStyle.Bold);
            openItem.Font = _trayOpenFont;
            openItem.Click += (_, _) => Dispatcher.Invoke(ShowMainWindow);

            var runItem = new System.Windows.Forms.ToolStripMenuItem("Run Pipeline Now");
            runItem.Click += (_, _) => _ = Task.Run(() => _orchestrator.RunPipelineAsync());

            var stopItem = new System.Windows.Forms.ToolStripMenuItem("Stop Current Run");
            stopItem.Click += (_, _) => _orchestrator.CancelCurrentRun();

            var copyUrlItem = new System.Windows.Forms.ToolStripMenuItem("Copy Local Subscription URL");
            copyUrlItem.Click += (_, _) => Dispatcher.Invoke(() =>
            {
                try
                {
                    Clipboard.SetText(_localServer.SubscriptionUrl);
                    _trayIcon?.ShowBalloonTip(2000, "V2SubAuto", $"Copied {_localServer.SubscriptionUrl}", System.Windows.Forms.ToolTipIcon.Info);
                }
                catch { }
            });

            var copyLanUrlItem = new System.Windows.Forms.ToolStripMenuItem("Copy LAN Subscription URL");
            copyLanUrlItem.Click += (_, _) => Dispatcher.Invoke(() =>
            {
                try
                {
                    if (!string.IsNullOrEmpty(_localServer.LanSubscriptionUrl))
                    {
                        Clipboard.SetText(_localServer.LanSubscriptionUrl);
                        _trayIcon?.ShowBalloonTip(2000, "V2SubAuto", $"Copied {_localServer.LanSubscriptionUrl}", System.Windows.Forms.ToolTipIcon.Info);
                    }
                    else
                    {
                        _trayIcon?.ShowBalloonTip(2500, "V2SubAuto", "LAN access is disabled or no LAN IP was detected.", System.Windows.Forms.ToolTipIcon.Warning);
                    }
                }
                catch { }
            });

            var exitItem = new System.Windows.Forms.ToolStripMenuItem("Exit");
            exitItem.Click += (_, _) => Dispatcher.Invoke(RequestExit);

            _trayMenu.Items.Add(openItem);
            _trayMenu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
            _trayMenu.Items.Add(runItem);
            _trayMenu.Items.Add(stopItem);
            _trayMenu.Items.Add(copyUrlItem);
            _trayMenu.Items.Add(copyLanUrlItem);
            _trayMenu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
            _trayMenu.Items.Add(exitItem);

            var initialTip = initialServingCount > 0
                ? $"V2SubAuto: Serving {initialServingCount} configs"
                : "V2SubAuto - Running";

            _trayIcon = new System.Windows.Forms.NotifyIcon
            {
                Icon = _generatedIcon,
                Text = initialTip.Length > 63 ? initialTip[..63] : initialTip,
                Visible = true,
                ContextMenuStrip = _trayMenu
            };

            _trayIcon.DoubleClick += (_, _) => Dispatcher.Invoke(ShowMainWindow);
        }

        private void ShowMainWindow()
        {
            if (_isExiting) return;
            if (!_mainWindow.IsVisible)
            {
                _mainWindow.Show();
            }
            if (_mainWindow.WindowState == WindowState.Minimized)
            {
                _mainWindow.WindowState = WindowState.Normal;
            }
            _mainWindow.Activate();
        }

        private void RequestExit()
        {
            if (_isExiting) return;
            _isExiting = true;

            try { _orchestrator.CancelCurrentRun(); } catch { }
            try { _orchestrator.Dispose(); } catch { }
            try { _localServer.Dispose(); } catch { }
            try { _coreRunner.Dispose(); } catch { }
            try { _coreRunner.CleanupTempDirectory(); } catch { }

            if (_trayIcon != null)
            {
                _trayIcon.Visible = false;
                _trayIcon.ContextMenuStrip = null;
                _trayIcon.Dispose();
                _trayIcon = null;
            }

            _trayMenu?.Dispose();
            _trayMenu = null;

            _trayOpenFont?.Dispose();
            _trayOpenFont = null;

            _generatedIcon?.Dispose();
            _generatedIcon = null;

            _mainWindow.AllowClose();
            _mainWindow.Close();

            try { _singleInstanceMutex?.ReleaseMutex(); } catch { }
            _singleInstanceMutex?.Dispose();
            _singleInstanceMutex = null;

            Shutdown();
        }

        private static Icon CreateTrayIcon()
        {
            try
            {
                var resourceInfo = GetResourceStream(new Uri("pack://application:,,,/Assets/app.ico"));
                if (resourceInfo?.Stream != null)
                {
                    using var stream = resourceInfo.Stream;
                    return new Icon(stream, new System.Drawing.Size(32, 32));
                }
            }
            catch
            {
                // Fall back to generated vector icon if resource loading fails
            }

            using var bmp = new Bitmap(32, 32);
            using var g = Graphics.FromImage(bmp);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);

            using var bgBrush = new SolidBrush(Color.FromArgb(59, 130, 246));
            g.FillEllipse(bgBrush, 1, 1, 30, 30);

            using var font = new Font("Segoe UI", 11, System.Drawing.FontStyle.Bold, GraphicsUnit.Pixel);
            using var textBrush = new SolidBrush(Color.White);
            using var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
            g.DrawString("V2", font, textBrush, new RectangleF(0, 1, 32, 31), sf);

            IntPtr hIcon = bmp.GetHicon();
            try
            {
                using var temp = Icon.FromHandle(hIcon);
                return (Icon)temp.Clone();
            }
            finally
            {
                DestroyIcon(hIcon);
            }
        }
    }
}
