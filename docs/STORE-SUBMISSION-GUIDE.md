# LocalCam Microsoft Store Submission Guide

Status: Maintained release procedure

This document is the operational source of truth for creating and submitting a LocalCam MSIX package to Microsoft Store. Product requirements remain in `docs/requirements/`; this guide defines the release steps and evidence.

## Authority and scope

- The package project is `LocalCam.Package\LocalCam.Package.wapproj`.
- The package manifest is `LocalCam.Package\Package.appxmanifest`.
- The package version is the manifest `Package/Identity/@Version` value. The `LocalCam.csproj` assembly and file versions are not the Store package version.
- The current package architecture policy is x64-only. Do not add x86, ARM64, or a multi-architecture bundle without an explicit policy change.
- LocalCam does not implement an in-app updater. Microsoft Store manages delivery of published package updates.
- Partner Center is authoritative for the latest submitted, published, and flighted version. Local generated artifacts and `_upkginfo.txt` are only local safeguards.

This guide covers MSIX Store submissions, not unpackaged Debug releases, EXE/MSI submissions, Store listing copy, pricing, or entitlement policy.

## Fixed package identity

Verify these values against the existing Partner Center product before changing the manifest:

| Property | Repository value |
|---|---|
| Identity Name | `JustinTagardaSoftware.LocalCam` |
| Identity Publisher | `CN=68EC506E-4B5E-416B-93E8-BA707CA3BE0F` |
| DisplayName | `LocalCam` |
| PublisherDisplayName | `JustinTagarda` |
| TargetDeviceFamily | `Windows.Desktop` |
| Minimum OS | `10.0.19041.0` |
| Architecture | `x64` |

Do not invent replacement identity or publisher values. If Partner Center differs from the repository, stop and resolve the identity discrepancy before packaging.

## Versioning procedure

1. Open `LocalCam.Package\Package.appxmanifest`.
2. Read the current `Identity Version`.
3. Check Partner Center for the highest applicable version already submitted or published for this product.
4. Select the next release version. Unless a release decision explicitly specifies another version, retain the current Major and Minor components and increment the Build component by one from the highest relevant Partner Center version. For example, `1.0.33.0` becomes `1.0.34.0`.
5. Use the format `Major.Minor.Build.0`.
6. Keep the fourth component equal to `0`. The first three components must be valid non-negative package version components, and the first component must not be zero.
7. Confirm the resulting version is greater than the version being updated for the same applicable package identity and is not already used by a submitted, published, or flighted package.
8. Update only the manifest version unless the release also intentionally changes assembly/file versioning.
9. Record the old version, new version, reason, and Partner Center reference in the release evidence.

The version currently present in the repository is an implementation value, not a permanent release instruction. Do not copy it blindly for a new submission.

If Partner Center is unavailable, if the highest relevant version cannot be established, or if submitted, published, and flighted versions conflict, stop and request the authoritative version before editing the manifest. Do not guess or reuse a version.

## Prerequisites

Before building:

- Work from the repository root: `D:\Projects\LocalCam`.
- Confirm the intended source changes are committed or otherwise recorded.
- Confirm the manifest identity and version were reviewed.
- Confirm Visual Studio 2026 MSBuild and the Desktop Bridge packaging targets are installed.
- Confirm the pinned SDK is available:

```powershell
dotnet --version
```

The result must be exactly `10.0.400`, as required by `global.json`. Stop if another SDK is selected.

## Create the Store package

Run the full x64 Store packaging build:

```powershell
& "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" `
  .\LocalCam.Package\LocalCam.Package.wapproj `
  /t:Build `
  /p:Configuration=Release `
  /p:Platform=x64 `
  /p:RunAnalyzers=false `
  /m `
  /v:minimal
```

Successful output includes:

```text
Your package has been successfully created.
```

The Store upload artifact is:

```text
LocalCam.Package\AppPackages\LocalCam.Package_<version>_x64.msixupload
```

The build also creates a test MSIX under:

```text
LocalCam.Package\AppPackages\LocalCam.Package_<version>_x64_Test\
```

Upload the `.msixupload` file to Partner Center. Do not upload the test MSIX as the Store submission artifact.

## Local package verification

Before uploading, verify:

1. The build completed successfully.
2. The `.msixupload` file exists and has a nonzero size.
3. The version in the filename matches `Package.appxmanifest`.
4. The package is x64.
5. The package identity and publisher match the fixed identity table.
6. The package contains the intended release assets and no development-only content.
7. The SHA-256 hash of the upload file is recorded.
8. The generated test MSIX installs and launches on a supported Windows machine.
9. Core workflows operate in the packaged app: startup, discovery, playback, Settings, snapshot, recording, and shutdown.
10. No in-app update button, update dialog, package queue, or self-installation route is present.
11. Any build warnings are reviewed and recorded; do not silently treat warnings as certification evidence.

For release evidence, record at least:

```text
Package version:
Previous Partner Center version:
SDK version:
Upload artifact:
Upload SHA-256:
Local package validation:
Packaged smoke test:
Build warnings:
```

Microsoft's current MSIX package requirements recommend validating the release package before submission. Windows App Certification Kit validation may be used as an optional local check; Partner Center certification remains the official Store gate.

## Partner Center submission

1. Open the existing LocalCam product in Partner Center.
2. Create a new update submission.
3. Upload the exact `.msixupload` artifact generated above.
4. Confirm the package identity, version, architecture, target family, and package status.
5. Review the listing, properties, age rating, pricing/availability, and submission options as required by the release.
6. Add certification notes and test instructions when they help certification reviewers exercise the app.
7. Submit the update for certification.
8. Record the Partner Center submission ID, package version, submission date, and certification result.

Do not claim that a package is Store-submitted or certified based only on a successful local MSBuild run.

## Store-flight verification

For a release that changes the installed Store experience:

1. Install the previous published or flighted Store version on a test machine.
2. Publish the new package to an appropriate Store flight.
3. Confirm the test machine receives the update through Microsoft Store.
4. Confirm the installed package version is the intended new version.
5. Confirm existing settings and user data remain usable.
6. Recheck startup, discovery, playback, Settings, snapshot, recording, and shutdown.
7. Record the flight name, test account/device, prior version, updated version, date, result, and any Store delivery delay.

Store-flight verification is external evidence and cannot be replaced by local package generation.

## Release record

Complete this record for each submission:

```text
Release/version:
Previous published/flighted version:
Manifest version:
Identity verified against Partner Center: yes/no
SDK version:
Build command completed: yes/no
MSIXUPLOAD path:
MSIXUPLOAD SHA-256:
Local package validation result:
Packaged smoke-test result:
Partner Center submission ID:
Flight name and test device/account:
Certification result:
Production publication result:
Notes or follow-up:
```

## Official Microsoft references

- [App package requirements for MSIX apps](https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msix/app-package-requirements)
- [Create an app submission for an MSIX app](https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msix/create-app-submission)
- [App package updates](https://learn.microsoft.com/en-us/windows/msix/app-package-updates)
- [Package identity overview](https://learn.microsoft.com/en-us/windows/apps/desktop/modernize/package-identity-overview)
