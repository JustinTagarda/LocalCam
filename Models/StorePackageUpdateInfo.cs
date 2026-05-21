namespace LocalCam.Models {
    internal sealed record StorePackageUpdateInfo(
        string PackageFamilyName,
        string Version,
        string PackageIdentitySnapshot,
        bool IsMandatory);
}
