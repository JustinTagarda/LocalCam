using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;
using LocalCam.Models;
using LocalCam.Services;
using Microsoft.Win32;

namespace LocalCam {
    public partial class SettingsWindow : Window {
        private readonly LocalCamSettings _initialSettings;
        private LocalCamSettings _baselineSettings;
        private bool _isDirty;
        private bool _allowClose;
        private bool _credentialValidationShown;
        private string? _snapshotFolderPathValue;
        private string? _recordingFolderPathValue;
        private Func<Task>? _premiumUpgradeHandler;
        private bool _premiumUiVisible;
        private bool _isPremiumOwned;
        private bool _isPremiumPurchaseBusy;
        private const string RtspCredentialsInvalidMessage = "RTSP credentials are missing or invalid.";
        public bool DidSave { get; private set; }

        public SettingsWindow(LocalCamSettings settings, string versionText) {
            InitializeComponent();
            SettingsVersionTextBlock.Text = $"v{versionText}";
            _initialSettings = settings;
            _baselineSettings = CloneSettings(settings);

            RtspUsernameTextBox.Text = settings.RtspUsername;
            RtspPasswordBox.Password = settings.RtspPassword;
            StreamPathTextBox.Text = NormalizeStreamPath(settings.StreamPath);
            ReconnectRecentCamerasOnStartupCheckBox.IsChecked = settings.ReconnectRecentCamerasOnStartup ?? (settings.AutoDetectOnStartup && settings.AutoStreamVideo);
            ThemePreferenceComboBox.SelectedValue = settings.ThemePreference.ToString();
            _snapshotFolderPathValue = NormalizeSnapshotSaveFolder(settings.SnapshotSaveFolder);
            _recordingFolderPathValue = NormalizeRecordingSaveFolder(settings.RecordingSaveFolder);
            RefreshSnapshotFolderDisplay();
            RefreshRecordingFolderDisplay();
            UpdateCredentialPlaceholderVisibility();
            UpdateCommitState();
        }

        public LocalCamSettings Settings { get; private set; } = new();

        public void SetPremiumUpgradeHandler(Func<Task> handler) {
            ArgumentNullException.ThrowIfNull(handler);
            _premiumUpgradeHandler = handler;
            UpdatePremiumUiState();
        }

        public void ApplyPremiumUiState(bool isVisible, bool isPremiumOwned, bool isPurchaseBusy) {
            _premiumUiVisible = isVisible;
            _isPremiumOwned = isPremiumOwned;
            _isPremiumPurchaseBusy = isPurchaseBusy;
            UpdatePremiumUiState();
        }

        public void ShowInlineError(string message) {
            var text = (message ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(text)) {
                InlineErrorTextBlock.Text = string.Empty;
                InlineErrorTextBlock.Visibility = Visibility.Collapsed;
                return;
            }

            InlineErrorTextBlock.Text = text;
            InlineErrorTextBlock.Visibility = Visibility.Visible;
        }

        public void ShowCredentialValidation(bool focusUsername = false) {
            var usernameMissing = string.IsNullOrWhiteSpace(RtspUsernameTextBox.Text);
            var passwordMissing = string.IsNullOrWhiteSpace(RtspPasswordBox.Password);
            _credentialValidationShown = true;
            SetCredentialValidationState(usernameMissing, passwordMissing);
            ShowInlineError(RtspCredentialsInvalidMessage);

            if (focusUsername) {
                Dispatcher.BeginInvoke(new Action(() => {
                    RtspUsernameTextBox.Focus();
                    RtspUsernameTextBox.SelectAll();
                }));
            }
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e) {
            TrySaveAndClose();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e) {
            Close();
        }

        private async void PremiumUpgradeButton_Click(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;

            if (_premiumUpgradeHandler is null || _isPremiumPurchaseBusy || _isPremiumOwned) {
                return;
            }

            _isPremiumPurchaseBusy = true;
            UpdatePremiumUiState();
            try {
                await _premiumUpgradeHandler();
            }
            finally {
                _isPremiumPurchaseBusy = false;
                UpdatePremiumUiState();
            }
        }

        private void UpdatePremiumUiState() {
            PremiumStatusTextBlock.Visibility = _premiumUiVisible
                ? Visibility.Visible
                : Visibility.Collapsed;
            PremiumStatusTextBlock.Text = _isPremiumOwned ? "Premium" : "Basic";

            var showUpgrade = _premiumUiVisible && !_isPremiumOwned && _premiumUpgradeHandler is not null;
            PremiumUpgradeButton.Visibility = showUpgrade
                ? Visibility.Visible
                : Visibility.Collapsed;
            PremiumUpgradeButton.IsEnabled = showUpgrade && !_isPremiumPurchaseBusy;
            PremiumUpgradeButton.Focusable = showUpgrade && !_isPremiumPurchaseBusy;
        }

        private void CameraSetupGuideHyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e) {
            try {
                Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) {
                    UseShellExecute = true
                });
            }
            catch (Exception ex) {
                JsonLogStore.Warning(
                    "camera_setup_guide_open_failed",
                    "Failed to open the camera setup guide in the default browser.",
                    "settings",
                    new Dictionary<string, object?> {
                        ["exceptionType"] = ex.GetType().Name
                    });
                MessageBox.Show(
                    this,
                    "Unable to open the camera setup guide. Please check your default browser settings.",
                    "Camera Setup Guide",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }

            e.Handled = true;
        }

        private void BrowseSnapshotFolderButton_Click(object sender, RoutedEventArgs e) {
            var picker = new OpenFolderDialog {
                Title = "Select snapshot save folder",
                Multiselect = false
            };

            if (!string.IsNullOrWhiteSpace(_snapshotFolderPathValue)) {
                picker.InitialDirectory = _snapshotFolderPathValue;
            }
            else {
                picker.InitialDirectory = GetDefaultSnapshotFolderPath();
            }

            var result = picker.ShowDialog(this);
            if (result == true && !string.IsNullOrWhiteSpace(picker.FolderName)) {
                _snapshotFolderPathValue = NormalizeSnapshotSaveFolder(picker.FolderName.Trim());
                RefreshSnapshotFolderDisplay();
                UpdateCommitState();
            }
        }

        private void ResetSnapshotFolderButton_Click(object sender, RoutedEventArgs e) {
            _snapshotFolderPathValue = null;
            RefreshSnapshotFolderDisplay();
            UpdateCommitState();
        }

        private void BrowseRecordingFolderButton_Click(object sender, RoutedEventArgs e) {
            var picker = new OpenFolderDialog {
                Title = "Select recording save folder",
                Multiselect = false
            };

            if (!string.IsNullOrWhiteSpace(_recordingFolderPathValue)) {
                picker.InitialDirectory = _recordingFolderPathValue;
            }
            else {
                picker.InitialDirectory = GetDefaultRecordingFolderPath();
            }

            var result = picker.ShowDialog(this);
            if (result == true && !string.IsNullOrWhiteSpace(picker.FolderName)) {
                _recordingFolderPathValue = NormalizeRecordingSaveFolder(picker.FolderName.Trim());
                RefreshRecordingFolderDisplay();
                UpdateCommitState();
            }
        }

        private void ResetRecordingFolderButton_Click(object sender, RoutedEventArgs e) {
            _recordingFolderPathValue = null;
            RefreshRecordingFolderDisplay();
            UpdateCommitState();
        }

        private void InputChanged(object sender, RoutedEventArgs e) {
            ShowInlineError(string.Empty);
            if (_credentialValidationShown) {
                UpdateCredentialValidationState();
            }
            UpdateCredentialPlaceholderVisibility();
            UpdateCommitState();
        }

        private void ThemePreferenceComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e) {
            _ = sender;
            _ = e;
            UpdateCommitState();
        }

        private void Window_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e) {
            if (e.Key == System.Windows.Input.Key.Escape) {
                e.Handled = true;
                Close();
            }
        }

        private void Window_Closing(object? sender, System.ComponentModel.CancelEventArgs e) {
            if (_allowClose || !_isDirty) {
                return;
            }

            var dialog = new UnsavedChangesDialog {
                Owner = this
            };

            var promptShown = dialog.ShowDialog();
            if (promptShown != true || dialog.Choice == UnsavedChangesChoice.ContinueEditing) {
                e.Cancel = true;
                return;
            }

            if (dialog.Choice == UnsavedChangesChoice.SaveAndClose) {
                    if (TrySaveOnly()) {
                    _allowClose = true;
                    DialogResult = true;
                    e.Cancel = false;
                    return;
                }
                e.Cancel = true;
                return;
            }

            if (dialog.Choice == UnsavedChangesChoice.DiscardChanges) {
                _allowClose = true;
                DialogResult = false;
                e.Cancel = false;
                return;
            }

            e.Cancel = true;
        }

        private void UpdateCommitState() {
            var current = BuildSettingsFromInputs();
            _isDirty = !SettingsEqual(current, _baselineSettings);
            SaveButton.IsEnabled = IsValid(current) && _isDirty;
        }

        private bool TrySaveAndClose() {
            if (!TrySaveOnly()) {
                return false;
            }

            _allowClose = true;
            DialogResult = true;
            Close();
            return true;
        }

        private bool TrySaveOnly() {
            var current = BuildSettingsFromInputs();
            if (!IsValid(current)) {
                return false;
            }

            if (!_isDirty) {
                return false;
            }

            try {
                SettingsStore.Save(current);
                Settings = current;
                DidSave = true;
                _baselineSettings = CloneSettings(current);
                _isDirty = false;
                UpdateCommitState();
                return true;
            }
            catch (Exception ex) {
                MessageBox.Show(
                    this,
                    $"Failed to save settings: {ex.Message}",
                    "Save Failed",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                _isDirty = true;
                UpdateCommitState();
                return false;
            }
        }

        private LocalCamSettings BuildSettingsFromInputs() {
            var current = CloneSettings(_initialSettings);
            current.RtspUsername = RtspUsernameTextBox.Text.Trim();
            current.RtspPassword = RtspPasswordBox.Password;
            current.StreamPath = NormalizeStreamPath(StreamPathTextBox.Text);
            current.ReconnectRecentCamerasOnStartup = ReconnectRecentCamerasOnStartupCheckBox.IsChecked == true;
            current.ThemePreference = ParseThemePreference(ThemePreferenceComboBox.SelectedValue as string);
            current.SnapshotSaveFolder = _snapshotFolderPathValue;
            current.RecordingSaveFolder = _recordingFolderPathValue;
            return current;
        }

        internal static void ApplyEditableSettings(LocalCamSettings target, LocalCamSettings source) {
            target.RtspUsername = source.RtspUsername;
            target.RtspPassword = source.RtspPassword;
            target.StreamPath = NormalizeStreamPath(source.StreamPath);
            target.ReconnectRecentCamerasOnStartup = source.ReconnectRecentCamerasOnStartup;
            target.ThemePreference = source.ThemePreference;
            target.SnapshotSaveFolder = source.SnapshotSaveFolder;
            target.RecordingSaveFolder = source.RecordingSaveFolder;
        }

        private static bool IsValid(LocalCamSettings settings) {
            return !string.IsNullOrWhiteSpace(NormalizeStreamPath(settings.StreamPath));
        }

        private void UpdateCredentialValidationState() {
            SetCredentialValidationState(
                string.IsNullOrWhiteSpace(RtspUsernameTextBox.Text),
                string.IsNullOrWhiteSpace(RtspPasswordBox.Password));
        }

        private void SetCredentialValidationState(bool usernameMissing, bool passwordMissing) {
            SetBorderBrushResource(RtspUsernameTextBox, usernameMissing ? "ErrorBrush" : "InputBorderBrush");
            SetBorderBrushResource(RtspPasswordBox, passwordMissing ? "ErrorBrush" : "InputBorderBrush");
        }

        private static void SetBorderBrushResource(Control control, string resourceKey) {
            control.SetResourceReference(Control.BorderBrushProperty, resourceKey);
        }

        private void UpdateCredentialPlaceholderVisibility() {
            RtspUsernamePlaceholderTextBlock.Visibility = string.IsNullOrWhiteSpace(RtspUsernameTextBox.Text)
                ? Visibility.Visible
                : Visibility.Collapsed;
            RtspPasswordPlaceholderTextBlock.Visibility = string.IsNullOrWhiteSpace(RtspPasswordBox.Password)
                ? Visibility.Visible
                : Visibility.Collapsed;
        }

        private static string NormalizeStreamPath(string? input) {
            var normalized = (input ?? string.Empty).Trim().TrimStart('/');
            return string.IsNullOrWhiteSpace(normalized)
                ? "stream1"
                : normalized;
        }

        private static string? NormalizeSnapshotSaveFolder(string? input) {
            return NormalizeKnownDefaultFolder(input, GetDefaultSnapshotFolderPath());
        }

        private static string? NormalizeRecordingSaveFolder(string? input) {
            return NormalizeKnownDefaultFolder(input, GetDefaultRecordingFolderPath());
        }

        private static string? NormalizeKnownDefaultFolder(string? input, string defaultPath) {
            var normalized = (input ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(normalized)) {
                return null;
            }

            var normalizedFullPath = GetNormalizedFullPath(normalized);
            var defaultFullPath = GetNormalizedFullPath(defaultPath);
            return string.Equals(normalizedFullPath, defaultFullPath, StringComparison.OrdinalIgnoreCase)
                ? null
                : normalized;
        }

        private static string GetDefaultSnapshotFolderPath() {
            var pictures = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);
            return string.IsNullOrWhiteSpace(pictures)
                ? "Pictures\\LocalCam"
                : System.IO.Path.Combine(pictures, "LocalCam");
        }

        private static string GetDefaultRecordingFolderPath() {
            var videos = Environment.GetFolderPath(Environment.SpecialFolder.MyVideos);
            return string.IsNullOrWhiteSpace(videos)
                ? "Videos\\LocalCam"
                : System.IO.Path.Combine(videos, "LocalCam");
        }

        private void RefreshSnapshotFolderDisplay() {
            var effectivePath = _snapshotFolderPathValue ?? GetDefaultSnapshotFolderPath();
            var displayText = GetUserFolderDisplayText(effectivePath);
            SnapshotFolderTextBox.Text = displayText;
            SnapshotFolderTextBox.ToolTip = effectivePath;
        }

        private void RefreshRecordingFolderDisplay() {
            var effectivePath = _recordingFolderPathValue ?? GetDefaultRecordingFolderPath();
            var displayText = GetUserFolderDisplayText(effectivePath);
            RecordingFolderTextBox.Text = displayText;
            RecordingFolderTextBox.ToolTip = effectivePath;
        }

        private static string GetUserFolderDisplayText(string fullPath) {
            var normalized = GetNormalizedFullPath(fullPath);
            var pictures = GetNormalizedFullPath(Environment.GetFolderPath(Environment.SpecialFolder.MyPictures));
            if (!string.IsNullOrWhiteSpace(pictures) &&
                string.Equals(normalized, GetNormalizedFullPath(System.IO.Path.Combine(pictures, "LocalCam")), StringComparison.OrdinalIgnoreCase)) {
                return "Pictures";
            }

            var videos = GetNormalizedFullPath(Environment.GetFolderPath(Environment.SpecialFolder.MyVideos));
            if (!string.IsNullOrWhiteSpace(videos) &&
                string.Equals(normalized, GetNormalizedFullPath(System.IO.Path.Combine(videos, "LocalCam")), StringComparison.OrdinalIgnoreCase)) {
                return "Videos";
            }

            var knownFolders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
                [GetNormalizedFullPath(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory))] = "Desktop",
                [GetNormalizedFullPath(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments))] = "Documents",
                [GetNormalizedFullPath(Environment.GetFolderPath(Environment.SpecialFolder.MyPictures))] = "Pictures",
                [GetNormalizedFullPath(Environment.GetFolderPath(Environment.SpecialFolder.MyVideos))] = "Videos",
                [GetNormalizedFullPath(Environment.GetFolderPath(Environment.SpecialFolder.MyMusic))] = "Music",
                [GetNormalizedFullPath(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"))] = "Downloads"
            };

            foreach (var folder in knownFolders) {
                if (!string.IsNullOrWhiteSpace(folder.Key) &&
                    string.Equals(normalized, folder.Key, StringComparison.OrdinalIgnoreCase)) {
                    return folder.Value;
                }
            }

            return fullPath;
        }

        private static string GetNormalizedFullPath(string path) {
            try {
                return System.IO.Path.GetFullPath(path)
                    .TrimEnd(System.IO.Path.DirectorySeparatorChar, System.IO.Path.AltDirectorySeparatorChar);
            }
            catch {
                return path.TrimEnd(System.IO.Path.DirectorySeparatorChar, System.IO.Path.AltDirectorySeparatorChar);
            }
        }

        private static AppThemePreference ParseThemePreference(string? value) {
            return Enum.TryParse(value, ignoreCase: true, out AppThemePreference preference)
                ? preference
                : AppThemePreference.System;
        }

        private static bool SettingsEqual(LocalCamSettings a, LocalCamSettings b) {
            return string.Equals(a.RtspUsername, b.RtspUsername, StringComparison.Ordinal) &&
                   string.Equals(a.RtspPassword, b.RtspPassword, StringComparison.Ordinal) &&
                   string.Equals(NormalizeStreamPath(a.StreamPath), NormalizeStreamPath(b.StreamPath), StringComparison.Ordinal) &&
                   string.Equals(NormalizeSnapshotSaveFolder(a.SnapshotSaveFolder), NormalizeSnapshotSaveFolder(b.SnapshotSaveFolder), StringComparison.Ordinal) &&
                   string.Equals(NormalizeRecordingSaveFolder(a.RecordingSaveFolder), NormalizeRecordingSaveFolder(b.RecordingSaveFolder), StringComparison.Ordinal) &&
                   a.ReconnectRecentCamerasOnStartup == b.ReconnectRecentCamerasOnStartup &&
                   a.ThemePreference == b.ThemePreference &&
                   string.Equals(a.LastSuccessfulDetectionMethod, b.LastSuccessfulDetectionMethod, StringComparison.Ordinal) &&
                   a.MainWindowLeft == b.MainWindowLeft &&
                   a.MainWindowTop == b.MainWindowTop &&
                   a.MainWindowWidth == b.MainWindowWidth &&
                   a.MainWindowHeight == b.MainWindowHeight;
        }

        internal static LocalCamSettings CloneSettings(LocalCamSettings settings) => SettingsStore.Clone(settings);
    }
}
