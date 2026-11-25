using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using V2SubAuto.Models;
using V2SubAuto.Services;

namespace V2SubAuto.Views
{
    public partial class MainWindow : Window
    {
        private static readonly SolidColorBrush BrushCoreOk = CreateFrozenBrush(52, 211, 153);
        private static readonly SolidColorBrush BrushCoreMissing = CreateFrozenBrush(251, 191, 36);
        private static readonly SolidColorBrush BrushBadgeRunning = CreateFrozenBrush(30, 58, 95);
        private static readonly SolidColorBrush BrushBadgeIdle = CreateFrozenBrush(15, 46, 34);
        private static readonly SolidColorBrush BrushLanActive = CreateFrozenBrush(52, 211, 153);
        private static readonly SolidColorBrush BrushLanMuted = CreateFrozenBrush(148, 163, 184);

        private AppSettings _settings;
        private readonly SettingsService _settingsService;
        private readonly LocalSubscriptionServer _localServer;
        private readonly PipelineOrchestrator _orchestrator;
        private readonly Action _exitAction;

        private readonly ObservableCollection<SubscriptionSource> _subscriptions = new();
        private readonly LinkedList<string> _logBuffer = new();
        private readonly ConcurrentQueue<string> _pendingLogs = new();
        private readonly DispatcherTimer _logFlushTimer;
        private const int MaxLogLines = 800;

        private bool _allowClose;
        private bool _isCommittingSubEdit;

        private static SolidColorBrush CreateFrozenBrush(byte r, byte g, byte b)
        {
            var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
            brush.Freeze();
            return brush;
        }

        public MainWindow(
            AppSettings settings,
            SettingsService settingsService,
            LocalSubscriptionServer localServer,
            PipelineOrchestrator orchestrator,
            Action exitAction)
        {
            InitializeComponent();

            _settings = settings;
            _settingsService = settingsService;
            _localServer = localServer;
            _orchestrator = orchestrator;
            _exitAction = exitAction;

            _logFlushTimer = new DispatcherTimer(DispatcherPriority.Background)
            {
                Interval = TimeSpan.FromMilliseconds(150)
            };
            _logFlushTimer.Tick += (_, _) => FlushPendingLogs();
            _logFlushTimer.Start();

            foreach (var u in AppSettings.PresetPingUrls) CmbPingUrl.Items.Add(u);
            foreach (var u in AppSettings.PresetSpeedTestUrls) CmbSpeedUrl.Items.Add(u);

            LoadSettingsIntoUi();
            RefreshCoreStatus();

            _localServer.OnLog += AppendLog;
            _orchestrator.OnLog += AppendLog;
            _orchestrator.OnSnapshotChanged += snapshot => Dispatcher.BeginInvoke(() => ApplySnapshot(snapshot));
            _orchestrator.OnSurvivingNodesChanged += nodes => Dispatcher.BeginInvoke(() =>
            {
                NodesGrid.ItemsSource = null;
                NodesGrid.ItemsSource = nodes;
            });

            ApplySnapshot(_orchestrator.CurrentSnapshot);
        }

        public void AllowClose() => _allowClose = true;

        public void LogWarning(string message)
        {
            AppendLog($"[{DateTime.Now:HH:mm:ss}] WARNING: {message}");
        }

        private void Window_Closing(object? sender, CancelEventArgs e)
        {
            if (!_allowClose)
            {
                e.Cancel = true;
                Hide();
            }
            else
            {
                _logFlushTimer.Stop();
            }
        }

        private void UpdateSubscriptionUrlDisplay()
        {
            TxtSubUrl.Text = _localServer.SubscriptionUrl;

            if (!_localServer.AllowLanAccess)
            {
                TxtLanSubUrl.Text = "Disabled (enable in Settings)";
                TxtLanSubUrl.Foreground = BrushLanMuted;
                BtnCopyLanUrl.IsEnabled = false;
            }
            else if (!string.IsNullOrEmpty(_localServer.LanSubscriptionUrl))
            {
                TxtLanSubUrl.Text = _localServer.LanSubscriptionUrl;
                TxtLanSubUrl.Foreground = BrushLanActive;
                BtnCopyLanUrl.IsEnabled = true;
            }
            else
            {
                TxtLanSubUrl.Text = $"Listening on 0.0.0.0:{_localServer.Port} (no LAN IP detected)";
                TxtLanSubUrl.Foreground = BrushLanMuted;
                BtnCopyLanUrl.IsEnabled = false;
            }
        }

        private void LoadSettingsIntoUi()
        {
            UpdateSubscriptionUrlDisplay();

            _subscriptions.Clear();
            foreach (var sub in _settings.Subscriptions)
            {
                _subscriptions.Add(new SubscriptionSource
                {
                    Name = sub.Name,
                    Url = sub.Url,
                    Enabled = sub.Enabled
                });
            }
            SubsGrid.ItemsSource = _subscriptions;

            ChkAutoStart.IsChecked = _settings.AutoStartWithWindows;
            ChkStartMinimized.IsChecked = _settings.StartMinimizedToTray;
            ChkRunOnStartup.IsChecked = _settings.RunImmediatelyOnStartup;
            ChkAutoSchedule.IsChecked = _settings.AutoScheduleEnabled;
            TxtIntervalMin.Text = _settings.RefreshIntervalMinutes.ToString(CultureInfo.InvariantCulture);

            TxtLocalPort.Text = _settings.LocalServerPort.ToString(CultureInfo.InvariantCulture);
            ChkAllowLan.IsChecked = _settings.AllowLanAccess;
            ChkAppendMetrics.IsChecked = _settings.AppendMetricsToRemarks;
            CmbSortOrder.SelectedIndex = _settings.OutputSortMode == SortOrderMode.DelayAscending ? 1 : 0;
            TxtMaxOutput.Text = _settings.MaxOutputConfigs.ToString(CultureInfo.InvariantCulture);

            ChkStepDedup.IsChecked = _settings.EnableDeduplication;
            ChkStepTcping.IsChecked = _settings.EnableTcpingTest;
            ChkStepRealDelay.IsChecked = _settings.EnableRealDelayTest;
            ChkStepSpeedTest.IsChecked = _settings.EnableSpeedTest;

            ChkKeepOlderDedup.IsChecked = _settings.KeepOlderDedupl;
            ChkAllowInsecure.IsChecked = _settings.AllowInsecureAndUnencrypted;
            TxtTcpingBatch.Text = _settings.TcpingBatchSize.ToString(CultureInfo.InvariantCulture);
            TxtTcpingTimeout.Text = _settings.TcpingTimeoutSeconds.ToString(CultureInfo.InvariantCulture);
            TxtRealPingBatch.Text = _settings.RealPingBatchSize.ToString(CultureInfo.InvariantCulture);
            TxtRealPingTimeout.Text = _settings.RealPingTimeoutSeconds.ToString(CultureInfo.InvariantCulture);
            TxtMixedConcurrency.Text = _settings.MixedConcurrencyCount.ToString(CultureInfo.InvariantCulture);
            CmbPingUrl.Text = _settings.RealPingTestUrl;
            CmbSpeedUrl.Text = _settings.SpeedTestUrl;
            TxtSpeedTimeout.Text = _settings.SpeedTestTimeoutSeconds.ToString(CultureInfo.InvariantCulture);
            TxtMinSpeed.Text = _settings.MinDownloadSpeedMBps.ToString("0.0", CultureInfo.InvariantCulture);

            TxtXrayPath.Text = _settings.XrayExecutablePath;
            TxtSingboxPath.Text = _settings.SingboxExecutablePath;
        }

        private void RefreshCoreStatus()
        {
            var xrayPath = _settingsService.ResolvePath(_settings.XrayExecutablePath);
            var sbPath = _settingsService.ResolvePath(_settings.SingboxExecutablePath);
            bool xrayOk = File.Exists(xrayPath);
            bool sbOk = File.Exists(sbPath);

            TxtCoreStatus.Text = $"Xray: {(xrayOk ? "Installed" : "Missing")}   |   sing-box: {(sbOk ? "Installed" : "Missing")}";
            TxtCoreStatus.Foreground = (xrayOk && sbOk) ? BrushCoreOk : BrushCoreMissing;
        }

        private void ApplySnapshot(PipelineSnapshot s)
        {
            TxtFetched.Text = s.FetchedCount.ToString("N0");
            TxtDedup.Text = s.AfterDedupCount.ToString("N0");
            TxtTcping.Text = s.AfterTcpingCount.ToString("N0");
            TxtRealDelay.Text = s.AfterRealDelayCount.ToString("N0");
            TxtServing.Text = s.FinalSurvivingCount.ToString("N0");

            TxtStage.Text = s.CurrentStage;
            TxtDetail.Text = s.DetailMessage;
            PipelineProgress.Value = s.ProgressPercent;

            TxtStatusBadge.Text = s.IsRunning ? "Running" : s.CurrentStage;
            StatusBadge.Background = s.IsRunning ? BrushBadgeRunning : BrushBadgeIdle;

            BtnRunNow.IsEnabled = !s.IsRunning;
            BtnStopRun.IsEnabled = s.IsRunning;

            var lastStr = s.LastCompletedUtc.HasValue
                ? $"Last: {s.LastCompletedUtc.Value.ToLocalTime():HH:mm:ss}"
                : "Last: —";
            var nextStr = s.NextScheduledUtc.HasValue
                ? $"Next: {s.NextScheduledUtc.Value.ToLocalTime():HH:mm:ss}"
                : "Auto-refresh paused";
            TxtScheduleInfo.Text = $"{lastStr}  |  {nextStr}";
        }

        private void AppendLog(string line)
        {
            _pendingLogs.Enqueue(line);
        }

        private void FlushPendingLogs()
        {
            if (_pendingLogs.IsEmpty) return;

            bool changed = false;
            while (_pendingLogs.TryDequeue(out var line))
            {
                _logBuffer.AddLast(line);
                changed = true;
            }

            if (!changed) return;

            while (_logBuffer.Count > MaxLogLines)
            {
                _logBuffer.RemoveFirst();
            }

            TxtLogs.Text = string.Join(Environment.NewLine, _logBuffer);
            TxtLogs.ScrollToEnd();
        }

        /// <summary>
        /// Safely finishes any active DataGrid edit transaction without re-entering RowEditEnding
        /// or throwing InvalidOperationException when switching tabs, sorting, or deleting rows.
        /// </summary>
        private bool CommitPendingSubsGridEdits()
        {
            if (_isCommittingSubEdit)
                return false;

            if (SubsGrid.Items is not IEditableCollectionView editableView ||
                (!editableView.IsEditingItem && !editableView.IsAddingNew))
            {
                return false;
            }

            _isCommittingSubEdit = true;
            try
            {
                try
                {
                    SubsGrid.CommitEdit(DataGridEditingUnit.Cell, true);
                    SubsGrid.CommitEdit(DataGridEditingUnit.Row, true);
                }
                catch (InvalidOperationException)
                {
                    // Fallback: ensure the EditItem transaction is closed so WPF never throws on DeferRefresh/Remove/Sort
                    try { SubsGrid.CancelEdit(DataGridEditingUnit.Row); } catch { }
                }
                return true;
            }
            finally
            {
                _isCommittingSubEdit = false;
            }
        }

        private void SaveSubscriptionsToSettings(bool logChange = true)
        {
            try
            {
                _settings.Subscriptions = _subscriptions
                    .Where(x => !string.IsNullOrWhiteSpace(x.Url))
                    .Select(x => new SubscriptionSource
                    {
                        Name = (x.Name ?? string.Empty).Trim(),
                        Url = x.Url.Trim(),
                        Enabled = x.Enabled
                    })
                    .ToList();

                _settingsService.Save(_settings);
                _orchestrator.UpdateSettings(_settings);

                if (logChange)
                {
                    int enabledCount = _settings.Subscriptions.Count(x => x.Enabled);
                    AppendLog($"[{DateTime.Now:HH:mm:ss}] Subscriptions synced ({enabledCount}/{_settings.Subscriptions.Count} enabled).");
                }
            }
            catch (Exception ex)
            {
                LogWarning($"Could not save subscriptions: {ex.Message}");
            }
        }

        private void SyncAndSaveSubscriptions(bool logChange = true)
        {
            CommitPendingSubsGridEdits();
            SaveSubscriptionsToSettings(logChange);
        }

        private void BtnRunNow_Click(object sender, RoutedEventArgs e)
        {
            SyncAndSaveSubscriptions(logChange: false);
            _ = Task.Run(() => _orchestrator.RunPipelineAsync());
        }

        private void BtnStopRun_Click(object sender, RoutedEventArgs e)
        {
            _orchestrator.CancelCurrentRun();
        }

        private void BtnHideToTray_Click(object sender, RoutedEventArgs e)
        {
            Hide();
        }

        private void BtnCopySubUrl_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Clipboard.SetText(_localServer.SubscriptionUrl);
                AppendLog($"[{DateTime.Now:HH:mm:ss}] Copied local subscription URL: {_localServer.SubscriptionUrl}");
            }
            catch { }
        }

        private void BtnCopyLanUrl_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_localServer.LanSubscriptionUrl)) return;
            try
            {
                Clipboard.SetText(_localServer.LanSubscriptionUrl);
                AppendLog($"[{DateTime.Now:HH:mm:ss}] Copied LAN subscription URL: {_localServer.LanSubscriptionUrl}");
            }
            catch { }
        }

        private void BtnAddSub_Click(object sender, RoutedEventArgs e)
        {
            var url = TxtNewSubUrl.Text.Trim();
            if (string.IsNullOrWhiteSpace(url))
            {
                MessageBox.Show("Please enter a valid subscription or config list URL.", "V2SubAuto", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            CommitPendingSubsGridEdits();

            var name = string.IsNullOrWhiteSpace(TxtNewSubName.Text)
                ? $"Subscription {_subscriptions.Count + 1}"
                : TxtNewSubName.Text.Trim();

            _subscriptions.Add(new SubscriptionSource { Name = name, Url = url, Enabled = true });
            TxtNewSubName.Clear();
            TxtNewSubUrl.Clear();

            SaveSubscriptionsToSettings();
        }

        private void BtnImportSubs_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Import Subscription URLs",
                Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                CheckFileExists = true,
                Multiselect = false
            };

            if (dialog.ShowDialog(this) != true)
                return;

            string[] lines;
            try
            {
                lines = File.ReadAllLines(dialog.FileName);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Could not read the selected file:\n{ex.Message}",
                    "V2SubAuto",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                return;
            }

            CommitPendingSubsGridEdits();

            var result = SubscriptionImportParser.ParseLines(
                lines,
                _subscriptions.Select(x => x.Url),
                _subscriptions.Count + 1);

            if (result.Added.Count > 0)
            {
                foreach (var sub in result.Added)
                {
                    _subscriptions.Add(sub);
                }

                SaveSubscriptionsToSettings(logChange: false);
            }

            var notes = new List<string>();
            if (result.DuplicateCount > 0)
                notes.Add($"{result.DuplicateCount} duplicate(s) skipped");
            if (result.InvalidLineCount > 0)
                notes.Add($"{result.InvalidLineCount} invalid line(s) ignored");

            var noteSuffix = notes.Count > 0 ? $" ({string.Join(", ", notes)})" : string.Empty;
            var fileName = Path.GetFileName(dialog.FileName);

            if (result.Added.Count > 0)
            {
                AppendLog($"[{DateTime.Now:HH:mm:ss}] Imported {result.Added.Count} subscription(s) from '{fileName}'{noteSuffix}.");
                MessageBox.Show(
                    $"Imported {result.Added.Count} subscription(s) from {fileName}{noteSuffix}.",
                    "V2SubAuto",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            else if (result.DuplicateCount > 0)
            {
                AppendLog($"[{DateTime.Now:HH:mm:ss}] No new subscriptions imported from '{fileName}'{noteSuffix}.");
                MessageBox.Show(
                    $"All valid URLs in {fileName} are already in your subscriptions list{noteSuffix}.",
                    "V2SubAuto",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show(
                    $"No valid http:// or https:// URLs were found in {fileName}.",
                    "V2SubAuto",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }

        private void BtnDeleteSub_Click(object sender, RoutedEventArgs e)
        {
            CommitPendingSubsGridEdits();

            var selectedItems = SubsGrid.SelectedItems.OfType<SubscriptionSource>().ToList();
            if (selectedItems.Count == 0)
                return;

            foreach (var item in selectedItems)
            {
                _subscriptions.Remove(item);
            }

            SaveSubscriptionsToSettings();
        }

        private void SubEnabledCheckBox_Click(object sender, RoutedEventArgs e)
        {
            // Defer so the TwoWay CheckBox binding updates the item before saving
            Dispatcher.BeginInvoke(DispatcherPriority.Background, () => SaveSubscriptionsToSettings());
        }

        private void SubsGrid_CellEditEnding(object? sender, DataGridCellEditEndingEventArgs e)
        {
            if (_isCommittingSubEdit || e.EditAction != DataGridEditAction.Commit)
                return;

            // Persist the edit after WPF completes cell commit; do not call CommitEdit here
            Dispatcher.BeginInvoke(DispatcherPriority.Background, () => SaveSubscriptionsToSettings(logChange: false));
        }

        private void SubsGrid_RowEditEnding(object? sender, DataGridRowEditEndingEventArgs e)
        {
            if (_isCommittingSubEdit || e.EditAction != DataGridEditAction.Commit)
                return;

            // Persist the edit after WPF completes row commit; do not re-enter CommitEdit here
            Dispatcher.BeginInvoke(DispatcherPriority.Background, () => SaveSubscriptionsToSettings());
        }

        private void SubsGrid_LostKeyboardFocus(object sender, KeyboardFocusChangedEventArgs e)
        {
            if (_isCommittingSubEdit || SubsGrid.IsKeyboardFocusWithin)
                return;

            Dispatcher.BeginInvoke(DispatcherPriority.Background, () =>
            {
                if (!SubsGrid.IsKeyboardFocusWithin && CommitPendingSubsGridEdits())
                {
                    SaveSubscriptionsToSettings();
                }
            });
        }

        private void SubsGrid_Sorting(object sender, DataGridSortingEventArgs e)
        {
            CommitPendingSubsGridEdits();
        }

        private void SubsGrid_Unloaded(object sender, RoutedEventArgs e)
        {
            if (CommitPendingSubsGridEdits())
            {
                SaveSubscriptionsToSettings(logChange: false);
            }
        }

        private void BtnSaveSubs_Click(object sender, RoutedEventArgs e)
        {
            SyncAndSaveSubscriptions();
            MessageBox.Show("Subscriptions saved.", "V2SubAuto", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void BtnSaveSettings_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var errors = new List<string>();

                if (!int.TryParse(TxtIntervalMin.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var interval) || interval < 1)
                    errors.Add("Refresh Interval (minutes) must be a whole number >= 1.");

                if (!int.TryParse(TxtLocalPort.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var port) || port < 1024 || port > 65535)
                    errors.Add("Local HTTP Port must be between 1024 and 65535.");

                if (!int.TryParse(TxtMaxOutput.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var maxOut) || maxOut < 0)
                    errors.Add("Max Output Configs must be a whole number >= 0.");

                if (!int.TryParse(TxtTcpingBatch.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var tcpBatch) || tcpBatch < 1)
                    errors.Add("Tcping Batch Size must be a whole number >= 1.");

                if (!int.TryParse(TxtTcpingTimeout.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var tcpTimeout) || tcpTimeout < 1)
                    errors.Add("Tcping Timeout (sec) must be a whole number >= 1.");

                if (!int.TryParse(TxtRealPingBatch.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var rpBatch) || rpBatch < 1)
                    errors.Add("Real Delay Batch must be a whole number >= 1.");

                if (!int.TryParse(TxtRealPingTimeout.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var rpTimeout) || rpTimeout < 2)
                    errors.Add("Real Delay Timeout (sec) must be a whole number >= 2.");

                if (!int.TryParse(TxtMixedConcurrency.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var mixConc) || mixConc < 1)
                    errors.Add("Speedtest Concurrency must be a whole number >= 1.");

                if (!int.TryParse(TxtSpeedTimeout.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var spTimeout) || spTimeout < 2)
                    errors.Add("Speedtest Timeout (sec) must be a whole number >= 2.");

                if (!double.TryParse(TxtMinSpeed.Text.Trim().Replace(',', '.'), NumberStyles.Float, CultureInfo.InvariantCulture, out var minSp) || minSp < 0)
                    errors.Add("Min Download Speed (MB/s) must be a number >= 0.");

                if (errors.Count > 0)
                {
                    MessageBox.Show(
                        "Please fix the following settings before saving:\n\n• " + string.Join("\n• ", errors),
                        "Invalid Settings",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                    return;
                }

                // Commit any pending subscription edits so Save Settings never overwrites them with stale data
                CommitPendingSubsGridEdits();
                _settings.Subscriptions = _subscriptions
                    .Where(x => !string.IsNullOrWhiteSpace(x.Url))
                    .Select(x => new SubscriptionSource
                    {
                        Name = (x.Name ?? string.Empty).Trim(),
                        Url = x.Url.Trim(),
                        Enabled = x.Enabled
                    })
                    .ToList();

                int oldPort = _settings.LocalServerPort;
                bool oldAllowLan = _settings.AllowLanAccess;

                _settings.AutoStartWithWindows = ChkAutoStart.IsChecked == true;
                _settings.StartMinimizedToTray = ChkStartMinimized.IsChecked == true;
                _settings.RunImmediatelyOnStartup = ChkRunOnStartup.IsChecked == true;
                _settings.AutoScheduleEnabled = ChkAutoSchedule.IsChecked == true;
                _settings.RefreshIntervalMinutes = interval;
                _settings.LocalServerPort = port;
                _settings.AllowLanAccess = ChkAllowLan.IsChecked == true;

                _settings.AppendMetricsToRemarks = ChkAppendMetrics.IsChecked == true;
                _settings.OutputSortMode = CmbSortOrder.SelectedIndex == 1
                    ? SortOrderMode.DelayAscending
                    : SortOrderMode.SpeedDescending;
                _settings.MaxOutputConfigs = maxOut;

                _settings.EnableDeduplication = ChkStepDedup.IsChecked == true;
                _settings.EnableTcpingTest = ChkStepTcping.IsChecked == true;
                _settings.EnableRealDelayTest = ChkStepRealDelay.IsChecked == true;
                _settings.EnableSpeedTest = ChkStepSpeedTest.IsChecked == true;

                _settings.KeepOlderDedupl = ChkKeepOlderDedup.IsChecked == true;
                _settings.AllowInsecureAndUnencrypted = ChkAllowInsecure.IsChecked == true;
                _settings.TcpingBatchSize = tcpBatch;
                _settings.TcpingTimeoutSeconds = tcpTimeout;
                _settings.RealPingBatchSize = rpBatch;
                _settings.RealPingTimeoutSeconds = rpTimeout;
                _settings.MixedConcurrencyCount = mixConc;

                if (!string.IsNullOrWhiteSpace(CmbPingUrl.Text))
                    _settings.RealPingTestUrl = CmbPingUrl.Text.Trim();
                if (!string.IsNullOrWhiteSpace(CmbSpeedUrl.Text))
                    _settings.SpeedTestUrl = CmbSpeedUrl.Text.Trim();

                _settings.SpeedTestTimeoutSeconds = spTimeout;
                _settings.MinDownloadSpeedMBps = minSp;

                if (!string.IsNullOrWhiteSpace(TxtXrayPath.Text))
                    _settings.XrayExecutablePath = TxtXrayPath.Text.Trim();
                if (!string.IsNullOrWhiteSpace(TxtSingboxPath.Text))
                    _settings.SingboxExecutablePath = TxtSingboxPath.Text.Trim();

                _settingsService.Save(_settings);
                AutoStartupService.Apply(_settings.AutoStartWithWindows);

                bool portWarning = false;
                if (oldPort != _settings.LocalServerPort || oldAllowLan != _settings.AllowLanAccess || !_localServer.IsRunning)
                {
                    bool started = _localServer.Start(_settings.LocalServerPort, _settings.AllowLanAccess);
                    UpdateSubscriptionUrlDisplay();
                    if (!started)
                    {
                        portWarning = true;
                        LogWarning($"Could not bind subscription server to port {_settings.LocalServerPort}.");
                    }
                }

                _orchestrator.UpdateSettings(_settings);
                RefreshCoreStatus();

                AppendLog($"[{DateTime.Now:HH:mm:ss}] Settings saved.");
                MessageBox.Show(
                    portWarning
                        ? $"Settings saved, but the subscription server could not bind to port {_settings.LocalServerPort}. Try another port."
                        : "Settings saved and applied.",
                    "V2SubAuto",
                    MessageBoxButton.OK,
                    portWarning ? MessageBoxImage.Warning : MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error saving settings: {ex.Message}", "V2SubAuto", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void BtnDownloadCores_Click(object sender, RoutedEventArgs e)
        {
            BtnDownloadCores.IsEnabled = false;
            BtnDownloadCores.Content = "Downloading Cores...";
            try
            {
                if (_orchestrator.CurrentSnapshot.IsRunning)
                {
                    AppendLog($"[{DateTime.Now:HH:mm:ss}] Cancelling active pipeline run before updating core binaries...");
                    _orchestrator.CancelCurrentRun();
                    await Task.Delay(500);
                }

                var xrayPath = _settingsService.ResolvePath(_settings.XrayExecutablePath);
                var sbPath = _settingsService.ResolvePath(_settings.SingboxExecutablePath);

                var (xrayOk, sbOk) = await CoreDownloaderService.DownloadLatestCoresAsync(
                    xrayPath, sbPath, msg => AppendLog($"[{DateTime.Now:HH:mm:ss}] {msg}"), CancellationToken.None);

                RefreshCoreStatus();
                MessageBox.Show(
                    $"Download finished.\nXray: {(xrayOk ? "OK" : "Failed")}\nsing-box: {(sbOk ? "OK" : "Failed")}",
                    "V2SubAuto",
                    MessageBoxButton.OK,
                    xrayOk && sbOk ? MessageBoxImage.Information : MessageBoxImage.Warning);
            }
            finally
            {
                BtnDownloadCores.Content = "Download / Update Latest Xray & sing-box";
                BtnDownloadCores.IsEnabled = true;
            }
        }

        private void BtnCopyLogs_Click(object sender, RoutedEventArgs e)
        {
            try { Clipboard.SetText(TxtLogs.Text); } catch { }
        }

        private void BtnClearLogs_Click(object sender, RoutedEventArgs e)
        {
            while (_pendingLogs.TryDequeue(out _)) { }
            _logBuffer.Clear();
            TxtLogs.Clear();
        }

        private void BtnExitApp_Click(object sender, RoutedEventArgs e)
        {
            _exitAction();
        }
    }
}
