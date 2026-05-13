using System.Windows;
using LocalCam.Models;
using LocalCam.Services;
using Microsoft.Win32;

namespace LocalCam {
    public partial class SettingsWindow : Window {
        private readonly LocalCamSettings _initialSettings;
        private LocalCamSettings _baselineSettings;
        private bool _isDirty;
        private bool _allowClose;
        private string? _snapshotFolderPathValue;
        public bool DidSave { get; private set; }

        public SettingsWindow(LocalCamSettings settings) {
            InitializeComponent();
            _initialSettings = settings;
            _baselineSettings = CloneSettings(settings);

            RtspUsernameTextBox.Text = settings.RtspUsername;
            RtspPasswordBox.Password = settings.RtspPassword;
            StreamPathTextBox.Text = settings.StreamPath;
            _snapshotFolderPathValue = NormalizeSnapshotSaveFolder(settings.SnapshotSaveFolder);
            RefreshSnapshotFolderDisplay();
            UpdateCommitState();
        }

        public LocalCamSettings Settings { get; private set; } = new();

        private void UpdateButton_Click(object sender, RoutedEventArgs e) {
            TrySaveAndClose();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e) {
            Close();
        }

        private void TitleBar_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e) {
            if (e.ButtonState == System.Windows.Input.MouseButtonState.Pressed) {
                DragMove();
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e) {
            Close();
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

        private void InputChanged(object sender, RoutedEventArgs e) {
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
            UpdateButton.IsEnabled = _isDirty && IsValid(current);
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
            if (!_isDirty || !IsValid(current)) {
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
            return new LocalCamSettings {
                RtspUsername = RtspUsernameTextBox.Text.Trim(),
                RtspPassword = RtspPasswordBox.Password,
                StreamPath = NormalizeStreamPath(StreamPathTextBox.Text),
                AutoStreamVideo = _initialSettings.AutoStreamVideo,
                SnapshotSaveFolder = _snapshotFolderPathValue,
                LastSuccessfulDetectionMethod = _initialSettings.LastSuccessfulDetectionMethod,
                MainWindowLeft = _initialSettings.MainWindowLeft,
                MainWindowTop = _initialSettings.MainWindowTop,
                MainWindowWidth = _initialSettings.MainWindowWidth,
                MainWindowHeight = _initialSettings.MainWindowHeight
            };
        }

        private static bool IsValid(LocalCamSettings settings) {
            return !string.IsNullOrWhiteSpace(NormalizeStreamPath(settings.StreamPath));
        }

        private static string NormalizeStreamPath(string? input) {
            var normalized = (input ?? string.Empty).Trim().TrimStart('/');
            return string.IsNullOrWhiteSpace(normalized)
                ? "stream1"
                : normalized;
        }

        private static string? NormalizeSnapshotSaveFolder(string? input) {
            var normalized = (input ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(normalized)) {
                return null;
            }

            var defaultPath = GetDefaultSnapshotFolderPath();
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

        private void RefreshSnapshotFolderDisplay() {
            var effectivePath = _snapshotFolderPathValue ?? GetDefaultSnapshotFolderPath();
            var displayText = GetUserFolderDisplayText(effectivePath);
            SnapshotFolderTextBox.Text = displayText;
            SnapshotFolderTextBox.ToolTip = effectivePath;
        }

        private static string GetUserFolderDisplayText(string fullPath) {
            var normalized = GetNormalizedFullPath(fullPath);
            var pictures = GetNormalizedFullPath(Environment.GetFolderPath(Environment.SpecialFolder.MyPictures));
            if (!string.IsNullOrWhiteSpace(pictures) &&
                string.Equals(normalized, GetNormalizedFullPath(System.IO.Path.Combine(pictures, "LocalCam")), StringComparison.OrdinalIgnoreCase)) {
                return "Pictures";
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

        private static bool SettingsEqual(LocalCamSettings a, LocalCamSettings b) {
            return string.Equals(a.RtspUsername, b.RtspUsername, StringComparison.Ordinal) &&
                   string.Equals(a.RtspPassword, b.RtspPassword, StringComparison.Ordinal) &&
                   string.Equals(NormalizeStreamPath(a.StreamPath), NormalizeStreamPath(b.StreamPath), StringComparison.Ordinal) &&
                   string.Equals(NormalizeSnapshotSaveFolder(a.SnapshotSaveFolder), NormalizeSnapshotSaveFolder(b.SnapshotSaveFolder), StringComparison.Ordinal) &&
                   a.AutoStreamVideo == b.AutoStreamVideo &&
                   string.Equals(a.LastSuccessfulDetectionMethod, b.LastSuccessfulDetectionMethod, StringComparison.Ordinal) &&
                   a.MainWindowLeft == b.MainWindowLeft &&
                   a.MainWindowTop == b.MainWindowTop &&
                   a.MainWindowWidth == b.MainWindowWidth &&
                   a.MainWindowHeight == b.MainWindowHeight;
        }

        private static LocalCamSettings CloneSettings(LocalCamSettings settings) {
            return new LocalCamSettings {
                RtspUsername = settings.RtspUsername,
                RtspPassword = settings.RtspPassword,
                StreamPath = settings.StreamPath,
                AutoStreamVideo = settings.AutoStreamVideo,
                SnapshotSaveFolder = settings.SnapshotSaveFolder,
                LastSuccessfulDetectionMethod = settings.LastSuccessfulDetectionMethod,
                MainWindowLeft = settings.MainWindowLeft,
                MainWindowTop = settings.MainWindowTop,
                MainWindowWidth = settings.MainWindowWidth,
                MainWindowHeight = settings.MainWindowHeight
            };
        }
    }
}
