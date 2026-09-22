using System.Text.Json;
using LocalCam.Services;
using Xunit;

namespace LocalCam.Tests;

public sealed class JsonLogStoreTests {
    [Fact]
    public void RedactSensitiveText_RemovesUrlsAndInlineCredentials() {
        var value = "Opening rtsp://camera-user:camera-password@192.168.1.10:554/stream1 with password=secret and token:abc123.";

        var redacted = JsonLogStore.RedactSensitiveText(value);

        Assert.DoesNotContain("camera-user", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("camera-password", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("rtsp://", redacted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("abc123", redacted, StringComparison.Ordinal);
        Assert.Contains("[REDACTED]", redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void SanitizeData_RedactsSensitiveKeysAndNestedValues() {
        var data = new Dictionary<string, object?> {
            ["username"] = "camera-user",
            ["password"] = "camera-password",
            ["ipAddress"] = "192.168.1.10",
            ["nested"] = new Dictionary<string, object?> {
                ["rtspUrl"] = "rtsp://camera-user:camera-password@192.168.1.10:554/stream1",
                ["status"] = "playing"
            }
        };

        var sanitized = JsonLogStore.SanitizeData(data);

        Assert.Equal("[REDACTED]", sanitized["username"]);
        Assert.Equal("[REDACTED]", sanitized["password"]);
        Assert.Equal("192.168.1.10", sanitized["ipAddress"]);
        var nested = Assert.IsType<Dictionary<string, object?>>(sanitized["nested"]);
        Assert.Equal("[REDACTED]", nested["rtspUrl"]);
        Assert.Equal("playing", nested["status"]);

        var serialized = JsonSerializer.Serialize(sanitized);
        Assert.DoesNotContain("camera-password", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("rtsp://", serialized, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PruneExpiredLogFiles_DeletesLogsOlderThanSevenDaysOnly() {
        var directory = Path.Combine(Path.GetTempPath(), "LocalCam-JsonLogStoreTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        try {
            var expiredPath = Path.Combine(directory, "localcam-expired.jsonl");
            var retainedPath = Path.Combine(directory, "localcam-retained.jsonl");
            File.WriteAllText(expiredPath, "expired");
            File.WriteAllText(retainedPath, "retained");

            var nowUtc = DateTime.UtcNow;
            File.SetLastWriteTimeUtc(expiredPath, nowUtc.AddDays(-7).AddMinutes(-1));
            File.SetLastWriteTimeUtc(retainedPath, nowUtc.AddDays(-6));

            JsonLogStore.PruneExpiredLogFiles(directory, nowUtc);

            Assert.False(File.Exists(expiredPath));
            Assert.True(File.Exists(retainedPath));
        }
        finally {
            if (Directory.Exists(directory)) {
                Directory.Delete(directory, recursive: true);
            }
        }
    }
}
