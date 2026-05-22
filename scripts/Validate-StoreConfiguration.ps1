param(
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $repoRoot "Package.appxmanifest"
$wapprojPath = Join-Path $repoRoot "LocalCam.Package.wapproj"
$storeAssociationPath = Join-Path $repoRoot "Package.StoreAssociation.xml"
$productConfigPath = Join-Path $repoRoot "Services\Store\StoreProductConfiguration.cs"
$storeUpdateClientPath = Join-Path $repoRoot "Services\StoreUpdateClient.cs"
$storeUpdateCoordinatorPath = Join-Path $repoRoot "Services\Updates\AppUpdateCoordinator.cs"
$docPath = Join-Path $repoRoot "store-assets\StoreConfiguration.md"

function Assert-Contains {
    param(
        [string]$Path,
        [string]$Pattern,
        [string]$Message
    )

    $content = Get-Content -LiteralPath $Path -Raw
    if ($content -notmatch $Pattern) {
        throw $Message
    }
}

[xml]$manifest = Get-Content -LiteralPath $manifestPath
if ($manifest.Package.Identity.Name -ne "JustinTagardaSoftware.LocalCam") {
    throw "Unexpected package identity name: $($manifest.Package.Identity.Name)"
}

if ($manifest.Package.Identity.Publisher -ne "CN=68EC506E-4B5E-416B-93E8-BA707CA3BE0F") {
    throw "Unexpected package publisher: $($manifest.Package.Identity.Publisher)"
}

if ([string]::IsNullOrWhiteSpace($manifest.Package.Identity.Version)) {
    throw "Package version is missing from Package.appxmanifest."
}

Assert-Contains -Path $wapprojPath -Pattern '<AppxBundlePlatforms>x64</AppxBundlePlatforms>' -Message "Package project is not limited to x64."
Assert-Contains -Path $wapprojPath -Pattern '<UapAppxPackageBuildMode>StoreUpload</UapAppxPackageBuildMode>' -Message "Package project is not configured for StoreUpload."
Assert-Contains -Path $productConfigPath -Pattern 'PremiumStoreId\s*=\s*"9P9KCJ3NFZFT"' -Message "Premium Store ID does not match the documented value."
Assert-Contains -Path $productConfigPath -Pattern 'PremiumProductId\s*=\s*"localcam_premium_lifetime"' -Message "Premium product ID does not match the documented value."
Assert-Contains -Path $storeUpdateClientPath -Pattern 'RequestDownloadStorePackageUpdatesAsync' -Message "Store update client is missing the direct Store download request path."
Assert-Contains -Path $storeUpdateClientPath -Pattern 'RequestDownloadAndInstallStorePackageUpdatesAsync' -Message "Store update client is missing the direct Store download-and-install request path."
Assert-Contains -Path $storeUpdateClientPath -Pattern 'TrySilentDownloadStorePackageUpdatesAsync' -Message "Store update client is missing the silent download path."
Assert-Contains -Path $storeUpdateClientPath -Pattern 'TrySilentDownloadAndInstallStorePackageUpdatesAsync' -Message "Store update client is missing the silent download-and-install path."
Assert-Contains -Path $storeUpdateCoordinatorPath -Pattern 'RunUserInitiatedUpdateFlowAsync' -Message "Store update coordinator is missing the user-initiated update flow."
Assert-Contains -Path $docPath -Pattern 'durable Microsoft Store add-on' -Message "Store configuration documentation is missing the durable add-on reference."

$association = [xml](Get-Content -LiteralPath $storeAssociationPath -Raw)
$ns = New-Object System.Xml.XmlNamespaceManager($association.NameTable)
$ns.AddNamespace("sa", "http://schemas.microsoft.com/appx/2010/storeassociation")

function Get-AssociationNodeText {
    param(
        [string]$XPath,
        [string]$Message
    )

    $node = $association.SelectSingleNode($XPath, $ns)
    if ($null -eq $node) {
        throw $Message
    }

    return $node.InnerText
}

function Get-AssociationAttrValue {
    param(
        [string]$XPath,
        [string]$AttributeName,
        [string]$Message
    )

    $node = $association.SelectSingleNode($XPath, $ns)
    if ($null -eq $node) {
        throw $Message
    }

    $value = $node.GetAttribute($AttributeName)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw $Message
    }

    return $value
}

$associationPublisher = Get-AssociationNodeText -XPath "//sa:StoreAssociation/sa:Publisher" -Message "Store association publisher is missing."
$associationPublisherDisplayName = Get-AssociationNodeText -XPath "//sa:StoreAssociation/sa:PublisherDisplayName" -Message "Store association publisher display name is missing."
$associationMainPackageIdentityName = Get-AssociationNodeText -XPath "//sa:StoreAssociation/sa:ProductReservedInfo/sa:MainPackageIdentityName" -Message "Store association main package identity is missing."
$associationReservedName = Get-AssociationNodeText -XPath "//sa:StoreAssociation/sa:ProductReservedInfo/sa:ReservedNames/sa:ReservedName" -Message "Store association reserved name is missing."
$associationLandingUrl = Get-AssociationAttrValue -XPath "//sa:StoreAssociation/sa:PackageInfoList" -AttributeName "LandingUrl" -Message "Store association landing URL is missing."
$associationPackageArchitecture = Get-AssociationNodeText -XPath "//sa:StoreAssociation/sa:PackageInfoList/sa:PackageInfo/sa:PackageArchitecture" -Message "Store association package architecture is missing."
$associationPackageMaxVersion = Get-AssociationNodeText -XPath "//sa:StoreAssociation/sa:PackageInfoList/sa:PackageInfo/sa:PackageMaxArchitectureVersion" -Message "Store association package max architecture version is missing."
$associationMinimumVersion = Get-AssociationNodeText -XPath "//sa:StoreAssociation/sa:PackageInfoList/sa:PackageInfo/sa:OsMinVersion" -Message "Store association minimum OS version is missing."

if ($associationPublisher -ne $manifest.Package.Identity.Publisher) {
    throw "Store association publisher does not match Package.appxmanifest."
}

if ($associationPublisherDisplayName -ne $manifest.Package.Properties.PublisherDisplayName) {
    throw "Store association publisher display name does not match Package.appxmanifest."
}

if ($associationMainPackageIdentityName -ne $manifest.Package.Identity.Name) {
    throw "Store association main package identity does not match Package.appxmanifest."
}

if ($associationReservedName -ne "localcam_premium_lifetime") {
    throw "Store association reserved name does not match the Premium product ID."
}

if ($associationLandingUrl -ne "ms-windows-store://pdp/?ProductId=9P9KCJ3NFZFT") {
    throw "Store association landing URL does not match the Premium product page."
}

if ($associationPackageArchitecture -ne "X64") {
    throw "Store association package architecture must be X64."
}

if ($associationPackageMaxVersion -ne $manifest.Package.Identity.Version) {
    throw "Store association package max architecture version does not match Package.appxmanifest."
}

if ($associationMinimumVersion -ne "10.0.19041.0") {
    throw "Store association minimum OS version must be 10.0.19041.0."
}

if (-not $Quiet) {
    Write-Host "Store configuration validation passed."
}
