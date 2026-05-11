namespace LocalCam.Models {
    internal sealed record StorePackageUpdateInfo(
        string PackageFamilyName,
        string Version,
        bool IsMandatory);
}
