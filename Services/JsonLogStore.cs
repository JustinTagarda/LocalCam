using System.IO;
using System.Text.Json;

namespace LocalCam.Services {
    internal static class JsonLogStore {
        private static readonly object SyncRoot = new();
        private static readonly JsonSerializerOptions JsonOptions = new() {
            WriteIndented = false
        };

        private static string LogDirectory {
            get {
                var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                return Path.Combine(root, "LocalCam", "logs");
            }
        }

        private static string GetLogPath() {
            return Path.Combine(LogDirectory, $"localcam-{DateTime.UtcNow:yyyyMMdd}.jsonl");
        }

        public static void Initialize() {
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
