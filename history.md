# LocalCam Development History and Engineering Guide

Last updated: 2026-03-01 (Asia/Manila)

## Purpose
This file is the authoritative project history for LocalCam.

Use it to:
- understand what was already implemented and why,
- avoid repeating refactors that were already tried/reverted,
- preserve stable behavior while adding new features,
- onboard new Codex sessions quickly with accurate context.

## Product Goal
LocalCam is a Windows desktop app for local-network Tapo camera discovery and live viewing.

Primary flow:
1. App starts.
2. Startup window scans local network for Tapo cameras.
3. If cameras are found, app opens main viewer.
4. If none are found, user can scan again or exit.

## Repository Milestones (Git)
- `a51c93c`: Initial commit (scanner + startup/main scaffolding).
- `13489fb`: README tech stack documentation.
- `dab21ce`: Startup flow window + dark borderless UI + custom title controls + icon assets.
- `1f52339`: RTSP live streaming integration in main viewer.
- `5d86516`: Added this history/engineering guide file.
- Local working changes (not yet pushed at time of writing):
  - aggressive scanner refactor,
  - startup diagnostics panel with candidate pass/fail reasons,
  - field troubleshooting logs in `logs/`.

## Chronological Change Log

### 1) Initial baseline analysis
Status at start:
- Template WPF app (`net10.0-windows`) with no camera logic.
- No NuGet dependencies.
- Empty `MainWindow`.

Outcome:
- Confirmed clean build.
- Established implementation path.

### 2) Local network Tapo scanner implemented
Added `Networking/TapoCameraScanner.cs` with:
- `TapoCameraDetection` result model.
- `ScanLocalNetworkForTapoCamerasAsync(...)` as primary API.
- Parallel host probing with cancellation support.
- Candidate signals:
  - open ports (`80`, `443`, `554`, `8554`, `2020`, `8080`, `8443`),
  - HTTP fingerprint markers (`tapo`, `tp-link`, `tplink`),
  - hostname markers,
  - TP-Link MAC OUI matching from ARP table.
- Subnet enumeration from active IPv4 interfaces with gateway filtering.
- `/24` cap for broad subnets to avoid excessive scan ranges.

Important scanner behavior:
- Returns "likely" Tapo devices based on weighted heuristics.
- Does not require internet/cloud APIs.

### 3) Scanner first UI integration (intermediate)
Main window initially had:
- scan/cancel buttons,
- progress/status,
- detection grid.

This phase validated scanner results but was later replaced by redesigned windows.

### 4) False-negative diagnosis and scanner hardening
Observed issue:
- user reported "no cameras detected" despite local cameras existing.

Actions taken:
- manually verified LAN hosts with camera-style ports (`554` + `2020`) were reachable.
- tuned detection scoring and signal combinations.
- expanded probe ports and strengthened fallback likelihood rules.

Result:
- improved practical detection reliability for local Tapo deployments.

### 5) Startup flow from user diagram
Flow implemented first in app startup logic, then finalized with a dedicated startup window:
- scan on app start,
- if found -> open main window,
- if not found -> allow scan again or exit.

Final startup orchestration:
- `App.xaml` no `StartupUri`.
- `App.xaml.cs` shows `StartupWindow` as gate before `MainWindow`.

### 6) Window design evolution (original and revised)

#### Design A (original app UI)
- classic WPF window,
- detection-oriented controls.

#### Design B (from provided mockups)
- dedicated startup scan screen,
- main window with 2x2 camera panels.

#### Design C (modern dark borderless)
- both startup and main windows changed to borderless dark style,
- custom title bars + custom window control buttons,
- app/window/taskbar icon support.

#### Design D (visual polish and bug fixes)
- removed unwanted dark frame around window edges,
- fixed rounded-corner clipping at top corners,
- refined titlebar button hover states (gray for min/max, red for close),
- corrected close-button highlight so top-right corner stays rounded,
- reduced window corner radius from 12 to 6,
- removed unnecessary `Live camera feeds` top label.

### 7) App icon and asset updates
Added `Assets/`:
- `security-camera.svg` (source icon),
- `security-camera.png`,
- `security-camera.ico`.

Project wiring:
- `ApplicationIcon` set in `LocalCam.csproj`.
- windows use `Icon="/Assets/security-camera.ico"`.

### 8) Titlebar controls refactor history
Implemented custom vector glyphs to match reference images:
- minimize (`-`),
- maximize/restore (square/restore),
- close (`X`).

Important fix history:
- one iteration mistakenly affected min/max when fixing close corner behavior,
- corrected so only close-button hover background uses top-right corner radius,
- min/max remain normal rectangular hover behavior.

### 9) RTSP live streaming implementation (current major feature)
Added real video playback in `MainWindow` using:
- `LibVLCSharp.WPF`
- `VideoLAN.LibVLC.Windows`

Main features:
- 4 `VideoView` surfaces (max 4 cameras displayed).
- runtime RTSP controls:
  - username,
  - password,
  - stream path (default `stream1`),
  - start/stop streaming.
- per-camera RTSP URL build:
  - `rtsp://<user>:<pass>@<camera-ip>:554/<streamPath>`
- startup labels include detected camera IPs.
- player disposal on window close to avoid resource leaks.

### 10) Operational tasks done
- created desktop shortcut:
  - `C:\Users\Justiniano\Desktop\LocalCam.lnk`
  - target: debug build executable.

### 11) Scanner robustness expansion + diagnostics instrumentation
Problem observed in some house deployments:
- scanner returned 0 likely cameras even when Tapo app could show video.

Scanner refactor updates:
- removed strict assumptions that reduced discovery reliability across varied home LAN topologies.
- added multi-source host seeding:
  - subnet host enumeration,
  - ARP table seeds,
  - ONVIF WS-Discovery hints,
  - TP-Link/Tapo broadcast hints.
- added adaptive large-subnet host sampling for broad prefixes.
- added retry/timeout hardening for TCP probe checks.
- expanded probe ports to include TP-Link/Tapo control ports (`20002`, `9999`).
- added direct TP-Link/Tapo UDP unicast probing per host (`20002`, `9999`).
- increased HTTP fingerprint depth:
  - probes multiple paths (`/`, `/index.html`, `/mainFrame.htm`, `/error.html`),
  - larger body capture limit to avoid missing late markers.
- added ARP-prime pass before probe cycle to improve neighbor visibility in noisy WLANs.
- added repeater/router fingerprint down-scoring to reduce false positives (e.g. `tplinkrepeater` UIs).

New scanner result models:
- `TapoCameraScanResult`
- `TapoScanDiagnostics`
- `TapoCameraCandidateDiagnostics`

Diagnostics now include:
- subnets scanned,
- enumerated host count,
- ARP seed count,
- ONVIF hint count,
- Tapo broadcast hint count,
- Tapo unicast hint count,
- responsive host count,
- per-candidate pass/fail reason and score.

### 12) Startup diagnostics UI upgrade
`StartupWindow` was expanded from minimal status/progress to full diagnostics view:
- larger resizable window to show scan evidence,
- summary counters for scan signals,
- subnet summary text,
- candidate `DataGrid` columns:
  - IP, pass/fail, score, open ports, ONVIF, Tapo UDP broadcast, Tapo UDP unicast, ARP, hostname, MAC, reason.

Purpose:
- make field troubleshooting explicit instead of opaque "no camera detected" outcomes.

### 13) Field troubleshooting findings (important context)
Live troubleshooting in problematic site showed:
- laptop and camera had same IPv4 subnet (`192.168.1.0/24`) in router client lists,
- camera IP (`192.168.1.9`) still unreachable from laptop (`destination host unreachable`),
- aggressive scan could only reach router and TP-Link repeater-style host (`192.168.1.11`),
- no reachable RTSP/ONVIF camera endpoints from the laptop despite Tapo app video availability.

Interpretation:
- same Layer-3 subnet does not guarantee Layer-2 client reachability.
- likely root cause in failed house is WLAN client isolation/inter-SSID bridging behavior (router firmware/policy), not only scanner logic.

## Current Architecture Snapshot

### Startup and navigation
- `App.xaml.cs`:
  - starts app in explicit shutdown mode,
  - opens `StartupWindow` first,
  - opens `MainWindow` only when startup scan returns cameras,
  - exits otherwise.

### Discovery layer
- `Networking/TapoCameraScanner.cs`:
  - standalone scanner service,
  - async + cancellation-aware,
  - multi-strategy discovery (subnet + ARP + ONVIF + Tapo UDP broadcast + Tapo UDP unicast),
  - aggressive retry/timeouts and deeper HTTP fingerprinting,
  - heuristic candidate scoring with repeater false-positive suppression,
  - diagnostics-rich scan result model.

### Startup UI
- `StartupWindow.xaml/.cs`:
  - auto-scan on load,
  - scan-again/exit actions,
  - status + progress updates,
  - scan diagnostics summary + subnet list + candidate reason table,
  - returns detection list to app startup.

### Viewer UI + playback
- `MainWindow.xaml/.cs`:
  - borderless dark main shell,
  - custom titlebar controls,
  - streaming credential controls,
  - 4 live video panels backed by LibVLC media players.

## Key Decisions and Rationale
- Local-first streaming: RTSP over LAN chosen for low latency and no cloud dependency.
- Heuristic detection instead of vendor cloud APIs: works offline and avoids account coupling.
- Startup gating: prevents entering main viewer when no camera candidates are available.
- Custom titlebar controls: required for borderless design and visual parity with references.
- Keep close-button corner handling isolated: avoids regressions in min/max behavior.
- Preserve scanner as evidence-driven and diagnostics-forward:
  - when detection fails, show concrete network signals and reasons in UI.
- Treat TP-Link repeater/admin signatures as non-camera by default unless camera-service evidence exists.

## Do-Not-Regress Rules (Important)
1. Do not reintroduce `StartupUri` in `App.xaml`; startup flow is code-controlled in `App.xaml.cs`.
2. Do not bypass `StartupWindow` gating unless intentionally redesigning app flow.
3. Keep `TitleBarCloseButtonStyle` corner radius fix scoped to close button only.
4. Keep window host background transparent for borderless rounded shape behavior.
5. Keep titlebar control buttons full titlebar height to avoid visual gaps.
6. Keep LibVLC disposal in `MainWindow.OnClosed`.
7. Keep scanner cancellation handling and multi-strategy discovery signals (ARP + ONVIF + Tapo broadcast + Tapo unicast).
8. Keep startup diagnostics table fields in sync with scanner diagnostics model.
9. Keep repeater/router false-positive suppression logic intact unless intentionally redesigned.

## Known Limitations
- Scanner identifies likely Tapo devices (heuristic), not absolute certainty.
- Live streaming requires valid RTSP credentials enabled in the Tapo app.
- Current viewer supports up to 4 simultaneous streams.
- RTSP path may vary per model/config (`stream1` default, `stream2` often available).
- In some ISP router firmware profiles, WLAN client isolation/inter-SSID bridge restrictions can block local camera reachability even within the same IPv4 subnet.
- Tapo app video can still appear functional via cloud relay when direct LAN ports are blocked; LocalCam requires local LAN reachability.

## Validation Checklist Before Any Major UI/Flow Change
- Build succeeds with no errors.
- Startup flow still works:
  - detect -> main opens,
  - none -> scan again/exit prompt stays usable.
- Titlebar controls still behave correctly:
  - min/max hover gray,
  - close hover red,
  - top-right corner remains rounded when close is hovered.
- Startup diagnostics still render and populate:
  - summary counters,
  - scanned subnet text,
  - candidate table with pass/fail reasons.
- At least one known camera stream can be started/stopped.
- Closing main window releases VLC resources cleanly.

## Recommendations for Future Development
1. Move streaming settings to persisted app config (username not stored in plain text unless user opts in).
2. Add per-tile connection state and retry logic.
3. Add camera selection UI when more than 4 cameras are detected.
4. Add diagnostics export (`.json`/`.txt`) for remote support and house-to-house comparisons.
5. Add manual IP reachability tool in startup UI (test specific host with ports `554/8554/2020/20002/9999`).
6. Add automated tests for scanner scoring and startup flow state transitions.

## Notes for New Codex Sessions
When starting fresh, read this file first, then inspect:
- `App.xaml.cs`
- `StartupWindow.xaml` and `StartupWindow.xaml.cs`
- `Networking/TapoCameraScanner.cs`
- `MainWindow.xaml` and `MainWindow.xaml.cs`
- `LocalCam.csproj`

Treat this as the stability contract unless the user explicitly asks for a design/flow reset.
