using System.IO;
using System.Text.Json;
using LocalCam.Models;

namespace LocalCam.Services.Updates {
    internal sealed class DeferredUpdateStateStore : IDeferredUpdateStateStore {
        private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

        private string StateDirectory {
            get {
                var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                return Path.Combine(root, "LocalCam");
            }
        }

        private string StatePath => Path.Combine(StateDirectory, "update-state.json");

        public async Task<DeferredUpdateState?> LoadAsync(CancellationToken cancellationToken) {
            if (!File.Exists(StatePath)) {
                return null;
            }

            await using var stream = File.OpenRead(StatePath);
            return await JsonSerializer.DeserializeAsync<DeferredUpdateState>(stream, JsonOptions, cancellationToken);
        }

        public async Task SaveAsync(DeferredUpdateState state, CancellationToken cancellationToken) {
            Directory.CreateDirectory(StateDirectory);
            await using var stream = File.Create(StatePath);
            await JsonSerializer.SerializeAsync(stream, state, JsonOptions, cancellationToken);
        }

        public Task ClearAsync(CancellationToken cancellationToken) {
            _ = cancellationToken;
            if (File.Exists(StatePath)) {
                File.Delete(StatePath);
            }

            return Task.CompletedTask;
        }
    }
}
