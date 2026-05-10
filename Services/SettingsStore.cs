using System.IO;
using System.Text.Json;
using LocalCam.Models;

namespace LocalCam.Services {
    internal static class SettingsStore {
        private static readonly JsonSerializerOptions JsonOptions = new() {
            WriteIndented = true
        };

        private static string SettingsDirectory {
            get {
                var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                return Path.Combine(root, "LocalCam");
            }
        }

        private static string SettingsPath => Path.Combine(SettingsDirectory, "settings.json");

        public static bool TryLoad(out LocalCamSettings settings) {
            try {
                if (!File.Exists(SettingsPath)) {
                    settings = new LocalCamSettings();
                    return false;
                }

                var json = File.ReadAllText(SettingsPath);
                settings = JsonSerializer.Deserialize<LocalCamSettings>(json, JsonOptions) ?? new LocalCamSettings();
                return true;
            }
            catch {
                settings = new LocalCamSettings();
                return false;
            }
        }

        public static void Save(LocalCamSettings settings) {
            Directory.CreateDirectory(SettingsDirectory);

            var json = JsonSerializer.Serialize(settings, JsonOptions);
            File.WriteAllText(SettingsPath, json);
        }
    }
}
