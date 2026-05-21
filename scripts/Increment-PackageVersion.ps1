param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath
)

if (-not (Test-Path -LiteralPath $ManifestPath)) {
    throw "Manifest not found: $ManifestPath"
}

[xml]$manifest = Get-Content -LiteralPath $ManifestPath
$identity = $manifest.Package.Identity
if ($null -eq $identity) {
    throw "Package Identity element not found in manifest: $ManifestPath"
}

$version = [string]$identity.Version
if ([string]::IsNullOrWhiteSpace($version)) {
    throw "Package Identity version is missing in manifest: $ManifestPath"
}

$parts = $version.Split('.')
if ($parts.Length -ne 4) {
    throw "Package Identity version must be Major.Minor.Build.Revision. Found: $version"
}

[int]$build = 0
if (-not [int]::TryParse($parts[2], [ref]$build)) {
    throw "Build component is not numeric in version: $version"
}

$parts[2] = ($build + 1).ToString()
$parts[3] = "0"
$newVersion = $parts -join '.'

$identity.Version = $newVersion
$manifest.Save($ManifestPath)

Write-Host "Package version incremented: $version -> $newVersion"
