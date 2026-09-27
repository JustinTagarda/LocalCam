using System.Text.Json;
using System.Text.Json.Nodes;
using LocalCam.Models;
using LocalCam.Services;
using Xunit;

namespace LocalCam.Tests;

[CollectionDefinition("SettingsStore", DisableParallelization = true)]
public sealed class SettingsStoreCollection {
}

[Collection("SettingsStore")]
public sealed class SettingsStoreTests {
    [Fact]
    public void TryLoadIgnoresObsoleteStoreUpdaterPropertiesWithoutDiscardingSettings() {
        var (directory, scope) = CreateSettingsDirectory();
        try {
            File.WriteAllText(
                Path.Combine(directory, "settings.json"),
                """
                {
                  "RtspUsername": "camera-user",
                  "StreamPath": "stream2",
                  "RecentCameraConnections": null,
                  "StoreUpdateCheckHistoryUtc": null,
                  "StoreUpdateLastKnownAvailable": true,
                  "StoreUpdateLastKnownPhase": "Downloading"
                }
                """);

            var loaded = SettingsStore.TryLoad(out var settings);

            Assert.True(loaded);
            Assert.Equal("camera-user", settings.RtspUsername);
            Assert.Equal("stream2", settings.StreamPath);
            Assert.Empty(settings.RecentCameraConnections);
            SettingsStore.Save(settings);
            var persistedJson = File.ReadAllText(Path.Combine(directory, "settings.json"));
            Assert.DoesNotContain("StoreUpdate", persistedJson);
        }
        finally {
            scope.Dispose();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void LegacyCameraRangeSettingIsDroppedAndValidatedRtspPortPersists() {
        var (directory, scope) = CreateSettingsDirectory();
        try {
            SettingsStore.Save(new LocalCamSettings {
                RecentCameraConnections = [new RecentCameraConnection {
                    IpAddress = "192.168.254.12",
                    RtspPort = 8554,
                    LastConfirmedPlaybackUtc = DateTimeOffset.UtcNow
                }]
            });
            var settingsPath = Path.Combine(directory, "settings.json");
            var legacyJson = JsonNode.Parse(File.ReadAllText(settingsPath))!;
            legacyJson["AdditionalCameraRanges"] = "192.168.254.0/24";
            File.WriteAllText(settingsPath, legacyJson.ToJsonString());

            Assert.True(SettingsStore.TryLoad(out var settings));
            Assert.Equal(8554, settings.RecentCameraConnections.Single().RtspPort);
            SettingsStore.Save(settings);
            Assert.DoesNotContain("AdditionalCameraRanges", File.ReadAllText(settingsPath));
        }
        finally {
            scope.Dispose();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void TryLoadRecoversFromBackupWhenPrimaryFileIsCorrupt() {
        var (directory, scope) = CreateSettingsDirectory();
        try {
            SettingsStore.Save(new LocalCamSettings {
                RtspUsername = "first-version",
                StreamPath = "stream1"
            });
            SettingsStore.Save(new LocalCamSettings {
                RtspUsername = "second-version",
                StreamPath = "stream2"
            });

            var settingsPath = Path.Combine(directory, "settings.json");
            var backupPath = Path.Combine(directory, "settings.json.bak");
            File.WriteAllText(settingsPath, "{ invalid json");

            var loaded = SettingsStore.TryLoad(out var settings);

            Assert.True(loaded);
            Assert.Equal("first-version", settings.RtspUsername);
            Assert.Equal("stream1", settings.StreamPath);
            Assert.True(File.Exists(backupPath));
        }
        finally {
            scope.Dispose();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void ConcurrentSavesLeaveValidJsonAndRecoverableSettings() {
        var (directory, scope) = CreateSettingsDirectory();
        try {
            Parallel.For(0, 32, index => {
                SettingsStore.Save(new LocalCamSettings {
                    RtspUsername = $"camera-user-{index}",
                    StreamPath = $"stream{index + 1}"
                });
            });

            var settingsPath = Path.Combine(directory, "settings.json");
            using var document = JsonDocument.Parse(File.ReadAllText(settingsPath));
            Assert.Equal(JsonValueKind.Object, document.RootElement.ValueKind);
            Assert.True(SettingsStore.TryLoad(out var settings));
            Assert.StartsWith("camera-user-", settings.RtspUsername);
            Assert.StartsWith("stream", settings.StreamPath);
        }
        finally {
            scope.Dispose();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void TryLoadFallsBackToDefaultsWhenPrimaryAndBackupAreInvalid() {
        var (directory, scope) = CreateSettingsDirectory();
        try {
            File.WriteAllText(Path.Combine(directory, "settings.json"), "{ invalid json");
            File.WriteAllText(Path.Combine(directory, "settings.json.bak"), "{ also invalid");

            var loaded = SettingsStore.TryLoad(out var settings);

            Assert.False(loaded);
            Assert.Equal(string.Empty, settings.RtspUsername);
            Assert.Equal("stream1", settings.StreamPath);
        }
        finally {
            scope.Dispose();
            Directory.Delete(directory, recursive: true);
        }
    }

    private static (string Directory, IDisposable Scope) CreateSettingsDirectory() {
        var directory = Path.Combine(Path.GetTempPath(), $"LocalCam.SettingsStoreTests.{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        return (directory, SettingsStore.UseSettingsDirectoryForTests(directory));
    }
}
