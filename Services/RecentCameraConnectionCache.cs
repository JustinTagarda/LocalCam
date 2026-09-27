using System.Net;
using LocalCam.Models;
using LocalCam.Networking;

namespace LocalCam.Services {
    public static class RecentCameraConnectionCache {
        public static readonly TimeSpan EntryLifetime = TimeSpan.FromDays(7);
        public const int ReconnectFailureEvictionThreshold = 2;

        public static bool PruneExpired(LocalCamSettings settings, DateTimeOffset now) {
            settings.RecentCameraConnections ??= new();
            var originalCount = settings.RecentCameraConnections.Count;
            settings.RecentCameraConnections = settings.RecentCameraConnections
                .Where(entry => entry is not null && IsValid(entry, now))
                .ToList();
            return settings.RecentCameraConnections.Count != originalCount;
        }

        public static IReadOnlyList<TapoCameraDetection> GetValidDetections(LocalCamSettings settings, DateTimeOffset now) {
            PruneExpired(settings, now);
            return settings.RecentCameraConnections
                .Select(entry => new TapoCameraDetection(
                    IPAddress.Parse(entry.IpAddress), entry.HostName, entry.MacAddress,
                    Array.Empty<int>(), 0, "Recent successful connection", entry.RtspPort is 554 or 8554 ? entry.RtspPort : 554))
                .ToArray();
        }

        public static void ConfirmPlayback(LocalCamSettings settings, TapoCameraDetection detection, DateTimeOffset now) {
            var entry = Find(settings, detection);
            if (entry is null) {
                entry = new RecentCameraConnection();
                settings.RecentCameraConnections.Add(entry);
            }

            entry.IpAddress = detection.IpAddress.ToString();
            entry.RtspPort = detection.RtspPort is 554 or 8554 ? detection.RtspPort : 554;
            entry.MacAddress = detection.MacAddress;
            entry.HostName = detection.HostName;
            entry.LastConfirmedPlaybackUtc = now;
            entry.ConsecutiveReconnectFailures = 0;
        }

        public static bool RegisterReconnectFailure(LocalCamSettings settings, TapoCameraDetection detection) {
            var entry = Find(settings, detection);
            if (entry is null) {
                return false;
            }

            entry.ConsecutiveReconnectFailures++;
            if (entry.ConsecutiveReconnectFailures < ReconnectFailureEvictionThreshold) {
                return false;
            }

            settings.RecentCameraConnections.Remove(entry);
            return true;
        }

        public static void InvalidateAll(LocalCamSettings settings) => settings.RecentCameraConnections.Clear();

        private static bool IsValid(RecentCameraConnection entry, DateTimeOffset now) {
            return IPAddress.TryParse(entry.IpAddress, out var address)
                && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                && entry.LastConfirmedPlaybackUtc > DateTimeOffset.MinValue
                && now - entry.LastConfirmedPlaybackUtc <= EntryLifetime;
        }

        private static RecentCameraConnection? Find(LocalCamSettings settings, TapoCameraDetection detection) {
            if (!string.IsNullOrWhiteSpace(detection.MacAddress)) {
                var byMac = settings.RecentCameraConnections.FirstOrDefault(entry =>
                    string.Equals(entry.MacAddress, detection.MacAddress, StringComparison.OrdinalIgnoreCase));
                if (byMac is not null) return byMac;
            }
            return settings.RecentCameraConnections.FirstOrDefault(entry =>
                string.Equals(entry.IpAddress, detection.IpAddress.ToString(), StringComparison.Ordinal));
        }
    }
}
