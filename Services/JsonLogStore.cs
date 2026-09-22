using System.Collections;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using Windows.Storage;

namespace LocalCam.Services {
    internal static class JsonLogStore {
        private const string InputDiagnosticsCategory = "InputDiagnostics";
        private const string VerboseLoggingEnvironmentVariable = "LOCALCAM_VERBOSE_LOGGING";
        private const string RedactedValue = "[REDACTED]";
        private const int RetentionDays = 7;
        private static readonly TimeSpan RetentionSweepInterval = TimeSpan.FromHours(1);
        private static readonly object SyncRoot = new();
        private static readonly JsonSerializerOptions JsonOptions = new() {
            WriteIndented = false
        };
        private static readonly bool IsVerboseLoggingEnabled = DetermineVerboseLoggingEnabled();
        private static readonly Regex UrlPattern = new(
            @"(?i)\b(?:rtsp|rtsps|https?|ftp)://[^\s""'<>]+",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex SensitiveAssignmentPattern = new(
            @"(?i)\b(password|passwd|username|user|token|secret|authorization|credential(?:s)?)\s*([:=])\s*([^\s,;\]}]+)",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static string? _logDirectory;
        private static DateTime _lastRetentionSweepUtc = DateTime.MinValue;

        private static string LogDirectory {
            get {
                return _logDirectory ??= ResolveLogDirectory();
            }
        }

        private static string GetLogPath() {
            return Path.Combine(LogDirectory, $"localcam-{DateTime.UtcNow:yyyyMMdd}.jsonl");
        }

        public static void Initialize() {
            try {
                lock (SyncRoot) {
                    EnsureLogDirectoryAndRetention(DateTime.UtcNow);
                }
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
            if (string.Equals(category, InputDiagnosticsCategory, StringComparison.OrdinalIgnoreCase) &&
                !IsVerboseLoggingEnabled) {
                return;
            }

            try {
                Initialize();

                var entry = new JsonLogEntry(
                    TimestampUtc: DateTimeOffset.UtcNow,
                    Level: level,
                    Category: category,
                    EventName: eventName,
                    Message: RedactSensitiveText(message),
                    Data: SanitizeData(data),
                    ExceptionType: exception?.GetType().FullName,
                    ExceptionMessage: exception is null ? null : RedactSensitiveText(exception.Message),
                    StackTrace: exception is null ? null : RedactSensitiveText(exception.StackTrace));

                var json = JsonSerializer.Serialize(entry, JsonOptions);

                lock (SyncRoot) {
                    EnsureLogDirectoryAndRetention(DateTime.UtcNow);
                    File.AppendAllText(GetLogPath(), json + Environment.NewLine);
                }
            }
            catch {
                // Logging is best-effort only.
            }
        }

        private static bool DetermineVerboseLoggingEnabled() {
            var rawValue = Environment.GetEnvironmentVariable(VerboseLoggingEnvironmentVariable);
            if (string.IsNullOrWhiteSpace(rawValue)) {
                return false;
            }

            return rawValue.Equals("1", StringComparison.OrdinalIgnoreCase)
                || rawValue.Equals("true", StringComparison.OrdinalIgnoreCase)
                || rawValue.Equals("yes", StringComparison.OrdinalIgnoreCase)
                || rawValue.Equals("on", StringComparison.OrdinalIgnoreCase);
        }

        internal static string RedactSensitiveText(string? value) {
            if (string.IsNullOrEmpty(value)) {
                return value ?? string.Empty;
            }

            var redacted = UrlPattern.Replace(value, RedactedValue);
            return SensitiveAssignmentPattern.Replace(
                redacted,
                match => $"{match.Groups[1].Value}{match.Groups[2].Value}{RedactedValue}");
        }

        internal static IReadOnlyDictionary<string, object?> SanitizeData(
            IReadOnlyDictionary<string, object?>? data) {
            if (data is null || data.Count == 0) {
                return new Dictionary<string, object?>();
            }

            var sanitized = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            foreach (var pair in data) {
                sanitized[pair.Key] = SanitizeValue(pair.Key, pair.Value);
            }

            return sanitized;
        }

        private static object? SanitizeValue(string? key, object? value) {
            if (IsSensitiveKey(key)) {
                return RedactedValue;
            }

            if (value is null) {
                return null;
            }

            if (value is string text) {
                return RedactSensitiveText(text);
            }

            if (value is Uri) {
                return RedactedValue;
            }

            if (value is byte[]) {
                return RedactedValue;
            }

            if (value is IReadOnlyDictionary<string, object?> readOnlyDictionary) {
                return SanitizeData(readOnlyDictionary);
            }

            if (value is IDictionary dictionary) {
                var sanitizedDictionary = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                foreach (DictionaryEntry entry in dictionary) {
                    var entryKey = entry.Key?.ToString() ?? string.Empty;
                    sanitizedDictionary[entryKey] = SanitizeValue(entryKey, entry.Value);
                }

                return sanitizedDictionary;
            }

            if (value is IEnumerable sequence) {
                var sanitizedSequence = new List<object?>();
                foreach (var item in sequence) {
                    sanitizedSequence.Add(SanitizeValue(null, item));
                }

                return sanitizedSequence;
            }

            return value;
        }

        private static bool IsSensitiveKey(string? key) {
            if (string.IsNullOrWhiteSpace(key)) {
                return false;
            }

            var normalized = key.Replace("_", string.Empty, StringComparison.Ordinal)
                .Replace("-", string.Empty, StringComparison.Ordinal)
                .Replace(" ", string.Empty, StringComparison.Ordinal);

            return normalized.Contains("password", StringComparison.OrdinalIgnoreCase)
                || normalized.Contains("passwd", StringComparison.OrdinalIgnoreCase)
                || normalized.Contains("username", StringComparison.OrdinalIgnoreCase)
                || normalized.Equals("user", StringComparison.OrdinalIgnoreCase)
                || normalized.Contains("token", StringComparison.OrdinalIgnoreCase)
                || normalized.Contains("secret", StringComparison.OrdinalIgnoreCase)
                || normalized.Contains("authorization", StringComparison.OrdinalIgnoreCase)
                || normalized.Contains("credential", StringComparison.OrdinalIgnoreCase)
                || normalized.Contains("rtspurl", StringComparison.OrdinalIgnoreCase);
        }

        private static string ResolveLogDirectory() {
            try {
                // For packaged builds, LocalFolder is package-owned app data and is removed by
                // Windows when the package is uninstalled.
                var packageLocalFolder = ApplicationData.Current.LocalFolder.Path;
                if (string.IsNullOrWhiteSpace(packageLocalFolder) || !Path.IsPathRooted(packageLocalFolder)) {
                    throw new InvalidOperationException("The package local application-data path is unavailable.");
                }

                return Path.Combine(packageLocalFolder, "logs");
            }
            catch {
                // Unpackaged desktop processes have no uninstall lifecycle. Keep the same
                // application-data route without ever writing beside the launched executable.
                var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (string.IsNullOrWhiteSpace(root)) {
                    root = Path.GetTempPath();
                }

                return Path.Combine(root, "LocalCam", "LocalState", "logs");
            }
        }

        private static void EnsureLogDirectoryAndRetention(DateTime nowUtc) {
            Directory.CreateDirectory(LogDirectory);
            if (nowUtc - _lastRetentionSweepUtc < RetentionSweepInterval) {
                return;
            }

            PruneExpiredLogFiles(LogDirectory, nowUtc);
            _lastRetentionSweepUtc = nowUtc;
        }

        internal static void PruneExpiredLogFiles(string directory, DateTime nowUtc) {
            var expirationUtc = nowUtc.AddDays(-RetentionDays);
            foreach (var path in Directory.EnumerateFiles(directory, "localcam-*.jsonl", SearchOption.TopDirectoryOnly)) {
                try {
                    if (File.GetLastWriteTimeUtc(path) < expirationUtc) {
                        File.Delete(path);
                    }
                }
                catch {
                    // Retention is best-effort; an in-use or inaccessible old file is retried later.
                }
            }
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
