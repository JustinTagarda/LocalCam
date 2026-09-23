using System.IO;
using System.Text.Json;
using System.Text;
using LocalCam.Models;

namespace LocalCam.Services {
    internal static class SettingsStore {
        private static readonly object Sync = new();
        private static readonly JsonSerializerOptions JsonOptions = new() {
            WriteIndented = true
        };
        private static string? _settingsDirectoryOverride;

        private static string SettingsDirectory {
            get {
                if (!string.IsNullOrWhiteSpace(_settingsDirectoryOverride)) {
                    return _settingsDirectoryOverride;
                }

                var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                return Path.Combine(root, "LocalCam");
            }
        }

        private static string SettingsPath => Path.Combine(SettingsDirectory, "settings.json");
        private static string SettingsBackupPath => Path.Combine(SettingsDirectory, "settings.json.bak");

        public static bool TryLoad(out LocalCamSettings settings) {
            lock (Sync) {
                var primaryPath = SettingsPath;
                var backupPath = SettingsBackupPath;
                Exception? primaryException = null;

                if (TryLoadFile(primaryPath, out settings, out primaryException)) {
                    return true;
                }

                Exception? backupException = null;
                if (TryLoadFile(backupPath, out settings, out backupException)) {
                    JsonLogStore.Warning(
                        eventName: "settings_recovered_from_backup",
                        message: "Recovered settings from the previous atomic settings backup.",
                        category: "settings",
                        data: new Dictionary<string, object?> {
                            ["settingsPath"] = primaryPath,
                            ["backupPath"] = backupPath,
                            ["primaryExceptionType"] = primaryException?.GetType().FullName,
                            ["backupUsed"] = true
                        });
                    return true;
                }

                if (primaryException is not null || backupException is not null) {
                    JsonLogStore.Warning(
                        eventName: "settings_load_failed",
                        message: "Failed to load settings from the primary file and backup.",
                        category: "settings",
                        data: new Dictionary<string, object?> {
                            ["settingsPath"] = primaryPath,
                            ["backupPath"] = backupPath,
                            ["primaryExceptionType"] = primaryException?.GetType().FullName,
                            ["backupExceptionType"] = backupException?.GetType().FullName,
                            ["primaryExceptionMessage"] = primaryException?.Message,
                            ["backupExceptionMessage"] = backupException?.Message
                        });
                }

                settings = new LocalCamSettings();
                return false;
            }
        }

        public static void Save(LocalCamSettings settings) {
            ArgumentNullException.ThrowIfNull(settings);

            lock (Sync) {
                Directory.CreateDirectory(SettingsDirectory);
                NormalizeSettings(settings);
                RecentCameraConnectionCache.PruneExpired(settings, DateTimeOffset.UtcNow);

                var snapshot = Clone(settings);
                var json = JsonSerializer.Serialize(snapshot, JsonOptions);
                WriteAtomically(json);
            }
        }

        internal static IDisposable UseSettingsDirectoryForTests(string directory) {
            ArgumentException.ThrowIfNullOrWhiteSpace(directory);

            lock (Sync) {
                var previous = _settingsDirectoryOverride;
                _settingsDirectoryOverride = directory;
                return new SettingsDirectoryOverrideScope(previous);
            }
        }

        internal static LocalCamSettings Clone(LocalCamSettings settings) {
            ArgumentNullException.ThrowIfNull(settings);

            return new LocalCamSettings {
                RtspUsername = settings.RtspUsername,
                RtspPassword = settings.RtspPassword,
                StreamPath = settings.StreamPath,
                AutoStreamVideo = settings.AutoStreamVideo,
                AutoDetectOnStartup = settings.AutoDetectOnStartup,
                ReconnectRecentCamerasOnStartup = settings.ReconnectRecentCamerasOnStartup,
                RecentCameraConnections = settings.RecentCameraConnections?.Where(entry => entry is not null).Select(CloneRecentConnection).ToList() ?? new(),
                ThemePreference = settings.ThemePreference,
                SnapshotSaveFolder = settings.SnapshotSaveFolder,
                RecordingSaveFolder = settings.RecordingSaveFolder,
                LastSuccessfulDetectionMethod = settings.LastSuccessfulDetectionMethod,
                HasVerifiedPremiumEntitlementCache = settings.HasVerifiedPremiumEntitlementCache,
                VerifiedPremiumEntitlementOwned = settings.VerifiedPremiumEntitlementOwned,
                VerifiedPremiumEntitlementCheckedUtc = settings.VerifiedPremiumEntitlementCheckedUtc,
                BasicRecordingUsageDateLocal = settings.BasicRecordingUsageDateLocal,
                BasicRecordingUsageSeconds = settings.BasicRecordingUsageSeconds,
                MainWindowLeft = settings.MainWindowLeft,
                MainWindowTop = settings.MainWindowTop,
                MainWindowWidth = settings.MainWindowWidth,
                MainWindowHeight = settings.MainWindowHeight,
                StoreUpdateCheckHistoryUtc = settings.StoreUpdateCheckHistoryUtc?.Where(value => value is not null).ToList() ?? new(),
                StoreUpdateLastKnownAvailable = settings.StoreUpdateLastKnownAvailable,
                StoreUpdateLastKnownPhase = settings.StoreUpdateLastKnownPhase,
                StoreUpdateLastKnownProgressPercent = settings.StoreUpdateLastKnownProgressPercent,
                StoreUpdateLastKnownDetailText = settings.StoreUpdateLastKnownDetailText,
                StoreUpdateLastKnownResultText = settings.StoreUpdateLastKnownResultText,
                StoreUpdateExpectedSubmissionState = settings.StoreUpdateExpectedSubmissionState,
                StoreUpdateExpectedRolloutMode = settings.StoreUpdateExpectedRolloutMode,
                StoreUpdateExpectedFlightAudience = settings.StoreUpdateExpectedFlightAudience
            };
        }

        private static bool TryLoadFile(string path, out LocalCamSettings settings, out Exception? exception) {
            settings = new LocalCamSettings();
            exception = null;

            if (!File.Exists(path)) {
                return false;
            }

            try {
                var json = File.ReadAllText(path);
                settings = JsonSerializer.Deserialize<LocalCamSettings>(json, JsonOptions) ?? new LocalCamSettings();
                NormalizeSettings(settings);
                RecentCameraConnectionCache.PruneExpired(settings, DateTimeOffset.UtcNow);
                return true;
            }
            catch (Exception ex) {
                exception = ex;
                return false;
            }
        }

        private static void NormalizeSettings(LocalCamSettings settings) {
            settings.StreamPath = NormalizeStreamPath(settings.StreamPath);
            settings.ReconnectRecentCamerasOnStartup ??= settings.AutoDetectOnStartup && settings.AutoStreamVideo;
            settings.AutoDetectOnStartup = false;
            settings.AutoStreamVideo = false;
            settings.RecentCameraConnections ??= new();
            settings.RecentCameraConnections = settings.RecentCameraConnections
                .Where(entry => entry is not null)
                .ToList();
            settings.StoreUpdateCheckHistoryUtc ??= new();
            settings.StoreUpdateCheckHistoryUtc = settings.StoreUpdateCheckHistoryUtc
                .Where(value => value is not null)
                .ToList();
            if (!Enum.IsDefined(settings.ThemePreference)) {
                settings.ThemePreference = AppThemePreference.System;
            }
        }

        private static void WriteAtomically(string json) {
            var settingsPath = SettingsPath;
            var temporaryPath = $"{settingsPath}.{Guid.NewGuid():N}.tmp";

            try {
                using (var stream = new FileStream(
                           temporaryPath,
                           FileMode.CreateNew,
                           FileAccess.Write,
                           FileShare.None,
                           bufferSize: 4096,
                           options: FileOptions.WriteThrough))
                using (var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), leaveOpen: true)) {
                    writer.Write(json);
                    writer.Flush();
                    stream.Flush(flushToDisk: true);
                }

                if (File.Exists(settingsPath)) {
                    File.Replace(temporaryPath, settingsPath, SettingsBackupPath, ignoreMetadataErrors: true);
                }
                else {
                    File.Move(temporaryPath, settingsPath);
                }
            }
            finally {
                if (File.Exists(temporaryPath)) {
                    File.Delete(temporaryPath);
                }
            }
        }

        private static RecentCameraConnection CloneRecentConnection(RecentCameraConnection entry) => new() {
            IpAddress = entry.IpAddress,
            MacAddress = entry.MacAddress,
            HostName = entry.HostName,
            DetectionMethod = entry.DetectionMethod,
            LastConfirmedPlaybackUtc = entry.LastConfirmedPlaybackUtc,
            ConsecutiveReconnectFailures = entry.ConsecutiveReconnectFailures
        };

        private sealed class SettingsDirectoryOverrideScope : IDisposable {
            private readonly string? _previous;
            private bool _disposed;

            public SettingsDirectoryOverrideScope(string? previous) {
                _previous = previous;
            }

            public void Dispose() {
                if (_disposed) {
                    return;
                }

                lock (Sync) {
                    _settingsDirectoryOverride = _previous;
                    _disposed = true;
                }
            }
        }

        private static string NormalizeStreamPath(string? input) {
            var normalized = (input ?? string.Empty).Trim().TrimStart('/');
            return string.IsNullOrWhiteSpace(normalized)
                ? "stream1"
                : normalized;
        }
    }
}
