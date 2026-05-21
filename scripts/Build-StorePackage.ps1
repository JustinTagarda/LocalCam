param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $repoRoot "Package.appxmanifest"
$wapprojPath = Join-Path $repoRoot "LocalCam.Package.wapproj"
$msbuildPath = "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"

if (-not (Test-Path -LiteralPath $msbuildPath)) {
    throw "MSBuild not found at Visual Studio 2026 path: $msbuildPath"
}

& (Join-Path $PSScriptRoot "Increment-PackageVersion.ps1") -ManifestPath $manifestPath

[xml]$manifest = Get-Content -LiteralPath $manifestPath
$version = [string]$manifest.Package.Identity.Version
if ([string]::IsNullOrWhiteSpace($version)) {
    throw "Failed to read package version from $manifestPath"
}

& $msbuildPath $wapprojPath `
    /t:Restore,Build `
    /p:Configuration=$Configuration `
    /p:Platform=$Platform `
    /p:UapAppxPackageBuildMode=StoreUpload `
    /p:AppxBundle=Never `
    /m
if ($LASTEXITCODE -ne 0) {
    throw "MSBuild packaging failed with exit code $LASTEXITCODE"
}

$appPackages = Join-Path $repoRoot "AppPackages"
$uploadRoot = Join-Path $repoRoot "bin\$Platform\$Configuration\Upload"
$keepPattern = [regex]::Escape($version)

if (Test-Path -LiteralPath $appPackages) {
    Get-ChildItem -LiteralPath $appPackages -Force |
        Where-Object { $_.Name -notmatch $keepPattern } |
        Remove-Item -Recurse -Force
}

if (Test-Path -LiteralPath $uploadRoot) {
    Get-ChildItem -LiteralPath $uploadRoot -Force |
        Where-Object { $_.Name -notmatch $keepPattern } |
        Remove-Item -Recurse -Force
}

$msixupload = Join-Path $appPackages ("LocalCam.Package_{0}_x64.msixupload" -f $version)
$msix = Join-Path $appPackages ("LocalCam.Package_{0}_x64_Test\LocalCam.Package_{0}_x64.msix" -f $version)

if (-not (Test-Path -LiteralPath $msixupload)) {
    throw "Expected Store upload artifact not found: $msixupload"
}
if (-not (Test-Path -LiteralPath $msix)) {
    throw "Expected x64 package artifact not found: $msix"
}

Write-Host "Store package build complete."
Write-Host "Version: $version"
Write-Host "MSIXUPLOAD: $msixupload"
Write-Host "MSIX: $msix"
