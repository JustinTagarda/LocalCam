using LocalCam.Networking;

namespace LocalCam.Services;

public static class CameraDetectionReconciler {
    public static IReadOnlyList<TapoCameraDetection> Reconcile(
        IReadOnlyList<TapoCameraDetection> previousDetections,
        IReadOnlyList<TapoCameraDetection> newDetections) {
        ArgumentNullException.ThrowIfNull(previousDetections);
        ArgumentNullException.ThrowIfNull(newDetections);

        var uniqueDetections = new List<TapoCameraDetection>(newDetections.Count);
        var indexByIdentity = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var detection in newDetections) {
            var identity = GetIdentity(detection, newDetections);
            if (!indexByIdentity.TryGetValue(identity, out var existingIndex)) {
                indexByIdentity.Add(identity, uniqueDetections.Count);
                uniqueDetections.Add(detection);
                continue;
            }

            if (detection.ConfidenceScore > uniqueDetections[existingIndex].ConfidenceScore) {
                uniqueDetections[existingIndex] = detection;
            }
        }

        var indexByIpAddress = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < uniqueDetections.Count; i++) {
            indexByIpAddress.TryAdd(uniqueDetections[i].IpAddress.ToString(), i);
        }

        var orderedDetections = new List<TapoCameraDetection>(uniqueDetections.Count);
        var used = new bool[uniqueDetections.Count];
        foreach (var previousDetection in previousDetections) {
            if (!indexByIdentity.TryGetValue(GetIdentity(previousDetection, previousDetections), out var index) &&
                !indexByIpAddress.TryGetValue(previousDetection.IpAddress.ToString(), out index)) {
                continue;
            }

            if (used[index]) {
                continue;
            }

            used[index] = true;
            orderedDetections.Add(uniqueDetections[index]);
        }

        for (var i = 0; i < uniqueDetections.Count; i++) {
            if (!used[i]) {
                orderedDetections.Add(uniqueDetections[i]);
            }
        }

        return orderedDetections;
    }

    public static string GetIdentity(TapoCameraDetection detection) {
        ArgumentNullException.ThrowIfNull(detection);
        return !string.IsNullOrWhiteSpace(detection.MacAddress)
            ? $"mac:{detection.MacAddress.Trim().ToUpperInvariant()}"
            : $"ip:{detection.IpAddress}";
    }

    public static string GetIdentity(
        TapoCameraDetection detection,
        IReadOnlyCollection<TapoCameraDetection> detections) {
        ArgumentNullException.ThrowIfNull(detection);
        ArgumentNullException.ThrowIfNull(detections);

        if (string.IsNullOrWhiteSpace(detection.MacAddress)) {
            return GetIdentity(detection);
        }

        var macIsSharedByDifferentAddresses = detections.Any(candidate =>
            !candidate.IpAddress.Equals(detection.IpAddress)
            && string.Equals(candidate.MacAddress?.Trim(), detection.MacAddress.Trim(), StringComparison.OrdinalIgnoreCase));

        return macIsSharedByDifferentAddresses
            ? $"ip:{detection.IpAddress}"
            : GetIdentity(detection);
    }
}
