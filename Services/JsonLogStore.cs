using System.IO;
using System.Text.Json;

namespace LocalCam.Services {
    internal static class JsonLogStore {
        private static readonly object SyncRoot = new();
        private static readonly JsonSerializerOptions JsonOptions = new() {
            WriteIndented = false
        };
        private static readonly bool IsLoggingEnabled = DetermineLoggingEnabled();

        private static string LogDirectory {
            get {
                return AppContext.BaseDirectory;
            }
        }

        private static string GetLogPath() {
            return Path.Combine(LogDirectory, $"localcam-{DateTime.UtcNow:yyyyMMdd}.jsonl");
        }

        public static void Initialize() {
            if (!IsLoggingEnabled) {
                return;
            }

            try {
                Directory.CreateDirectory(LogDirectory);
            }
            catch {
                // Logging is best-effort only.
            }
        }

        public static void Information(
            string eventName,
            string message,
            string category,
            IReadOnlyDictionary<string, object?>? data = null) {
            Write("Information", eventName, message, category, data, null);
        }

        public static void Warning(
            string eventName,
            string message,
            string category,
            IReadOnlyDictionary<string, object?>? data = null) {
            Write("Warning", eventName, message, category, data, null);
        }

        public static void Error(
            string eventName,
            string message,
            string category,
            Exception exception,
            IReadOnlyDictionary<string, object?>? data = null) {
            Write("Error", eventName, message, category, data, exception);
        }

        private static void Write(
            string level,
            string eventName,
            string message,
            string category,
            IReadOnlyDictionary<string, object?>? data,
            Exception? exception) {
            if (!IsLoggingEnabled) {
                return;
            }

            try {
                Initialize();

                var entry = new JsonLogEntry(
                    TimestampUtc: DateTimeOffset.UtcNow,
                    Level: level,
                    Category: category,
                    EventName: eventName,
                    Message: message,
                    Data: data,
                    ExceptionType: exception?.GetType().FullName,
                    ExceptionMessage: exception?.Message,
                    StackTrace: exception?.StackTrace);

                var json = JsonSerializer.Serialize(entry, JsonOptions);

                lock (SyncRoot) {
                    File.AppendAllText(GetLogPath(), json + Environment.NewLine);
                }
            }
            catch {
                // Logging is best-effort only.
            }
        }

        private static bool DetermineLoggingEnabled() {
#if !DEBUG
            return false;
#else
            return !IsInstalledDistribution();
#endif
        }

        private static bool IsInstalledDistribution() {
            if (IsPackagedProcess()) {
                return true;
            }

            var startupDirectory = Path.GetFullPath(AppContext.BaseDirectory)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

            return IsUnderPath(startupDirectory, programFiles)
                || IsUnderPath(startupDirectory, programFilesX86);
        }

        private static bool IsPackagedProcess() {
            var packageFamilyName = Environment.GetEnvironmentVariable("PACKAGE_FAMILY_NAME");
            if (!string.IsNullOrWhiteSpace(packageFamilyName)) {
                return true;
            }

            var appxPackageFamilyName = Environment.GetEnvironmentVariable("APPX_PACKAGE_FAMILY_NAME");
            return !string.IsNullOrWhiteSpace(appxPackageFamilyName);
        }

        private static bool IsUnderPath(string candidate, string root) {
            if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(root)) {
                return false;
            }

            var comparison = StringComparison.OrdinalIgnoreCase;
            return candidate.Equals(root, comparison)
                || candidate.StartsWith(root + Path.DirectorySeparatorChar, comparison)
                || candidate.StartsWith(root + Path.AltDirectorySeparatorChar, comparison);
        }

        private sealed record JsonLogEntry(
            DateTimeOffset TimestampUtc,
            string Level,
            string Category,
            string EventName,
            string Message,
            IReadOnlyDictionary<string, object?>? Data,
            string? ExceptionType,
            string? ExceptionMessage,
            string? StackTrace);
    }
}
