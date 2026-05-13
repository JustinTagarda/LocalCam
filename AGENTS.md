# LocalCam

## Inheritance Rule

- By default, follow [D:\Projects\AGENTS.md](D:\Projects\AGENTS.md).
- When this repo `AGENTS.md` provides project-specific instructions, those override global instructions.
- If there is no conflict, apply both global and repo-local instructions.

## Project Build Metadata

- `FAST_BUILD_PROJECT`: `LocalCam.csproj`
- `DEBUG_EXE_PATH`: `bin\Debug\net10.0-windows10.0.19041.0\LocalCam.exe`
- INSTANCE_MODE: `single-instance`

## Reusable Rules

- Mandatory enforcement: implement and keep behavior aligned with `D:\Projects\DEBUG-LOGGING.md`.
- Treat the workspace as the source of truth.
- Read local instructions first when they exist.
- Build a quick mental model before changing code.
- Inspect structure, entrypoints, config, core modules, data flow, and dependencies before editing.
- Search for existing patterns before introducing new ones.
- Prefer the existing architecture over idealized refactors.
- Make the smallest change that solves the problem.
- Verify facts in the codebase; do not speculate.
- If something is unclear, state `not found`.
- Preserve style, naming, and architecture.
- Avoid unrelated refactors.
- Do not overwrite user changes unless explicitly asked.
- Keep comments only when they add real clarity.
- Use ASCII by default unless the file already uses non-ASCII.
- Never assume missing files.
- Only modify provided files.
- Preserve existing user-facing controls by default.
- If a control must materially change to complete the task, stop first and explain what would change, why it is necessary, and what behavior would be lost or replaced.
- Keep the app lean.
- Before adding a package or heavy framework, ask whether built-in platform functionality can do the job.
- Add dependencies only when there is a clear project need and long-term maintenance cost is justified.
- Use minimal structured logging where it helps diagnose failures.
- Do not spam logs during normal interaction.
- Prefer a clear logging abstraction over scattered debug output.
- Prefer readability over cleverness.
- Use small focused methods.
- Use `async` and `await` correctly.
- Do not swallow exceptions silently.
- Avoid `async void` except for real event handlers.
- Do not edit, rewrite, regenerate, move, or delete `AGENTS.md` or similar instruction files unless explicitly asked.
- Treat instruction files as human-owned and read-only by default.
- Do not hardcode real runtime business data in code, prompts, defaults, or tests that behave like production data.
- Keep AI-facing prompt text in one owning file or prompt source per prompt.
- Do not duplicate prompt prose across files without a clear ownership reason.
- If the correct runtime store or owning prompt file is missing or unclear, stop and ask instead of inventing one.
- When asked to draw or describe control layouts, use ASCII tree format by default unless another format is requested.
- Prefer targeted tests or checks.
- Validate the affected path when the project has a known build or test command.
- Call out gaps if verification cannot be completed.
- Use the appropriate build mode for routine work rather than defaulting to a full build.
- Prefer the project’s required toolchain when builds are needed.
- A task is not done unless the code builds, fits the project structure, has no obvious dead code, has sensible behavior, handles failures reasonably, and remains maintainable.

## Current Implementation Snapshot

- Runtime/UI:
  - Single-window WPF desktop app (`MainWindow`) with custom window chrome.
  - Camera discovery runs on load and can be retried from the same window.
  - Up to 4 camera tiles are shown with expand/collapse behavior and responsive layout.
  - Settings dialog is available for RTSP credentials and stream path.
  - Auto-stream toggle is supported and persisted.

- Discovery:
  - Local-network discovery is heuristic and best-effort.
  - Scanner uses multi-method probing with persisted preferred detection method.
  - Detection and scan lifecycle statuses are surfaced in the main window.

- Streaming:
  - RTSP playback uses LibVLCSharp.
  - Start/stop controls are state-gated by scan state, stream state, and credentials.
  - Stream resources are cleaned up on stop/close.

- Persistence and diagnostics:
  - App settings persist at `%LocalAppData%\\LocalCam\\settings.json`.
  - Structured JSONL app diagnostics are written under `%LocalAppData%\\LocalCam\\logs`.

- Microsoft Store readiness:
  - Packaging project exists: `LocalCam.Package.wapproj`.
  - Manifest identity is configured for Store upload.
  - Store updater workflow is implemented in-app using `Windows.Services.Store` through service abstractions.
  - Footer update surface includes update state, progress, and restart affordance after install completion.

## LibVLCSharp.WPF.VideoView Overlay Policy

- Scope:
- Applies to all UI issues related to `LibVLCSharp.WPF.VideoView`: layering, overlays, click handling, badges, toolbars, and in-video controls.
- Default Rule:
- Implement overlay UI inside `VideoView` content.
- Treat this as mandatory for fixes and new UI behavior around `VideoView`.
- Do not place overlay controls as sibling WPF elements intended to appear above `VideoView`.
- Required Pattern:
- Place overlay controls as children/content of the `VideoView` host.
- Keep overlays local to each camera card and anchored to video bounds.
- Use standard WPF alignment/margins inside `VideoView` content for placement.
- Manage overlay z-order only within `VideoView` content.
- Validate during active streaming, not only when idle.
- Verification Checklist:
- Overlay stays visible while video is playing.
- Overlay moves and resizes with its camera card.
- Overlay interactions (click, hover, focus) work reliably.
- Behavior is correct in normal and expanded/collapsed card states.
- Behavior remains correct after window move, maximize/restore, and DPI scaling changes.
- Exception Handling:
- If in-`VideoView` overlay cannot satisfy a requirement, document:
- exact limitation
- reproducible steps
- expected vs actual behavior
- proposed fallback and tradeoffs
- Require explicit approval before implementing any fallback that uses separate overlay windows/surfaces.
- Guardrails:
- Keep changes minimal and localized to the affected card/video path.
- Do not mix multiple overlay strategies in one feature unless explicitly required.
- Avoid unrelated refactors while fixing `VideoView` UI issues.
- Definition of Done:
- Overlay behavior is stable under live streaming and window/layout changes.
- Controls remain visually attached to their owning camera card.
- No regression in existing camera card interactions.

## Button Accessibility and Visibility Policy

- Global:
- Hidden controls must not be keyboard-focusable or screen-reader actionable.
- Disabled controls that are marked always visible must remain visible but non-interactive.

- Top toolbar buttons:
- Detect Camera:
- always visible
- disable while detection is running
- enable when detection is not running
- Start All:
- always visible
- enable if one or more cards are not playing video
- disable if all cards are playing video
- Stop All:
- always visible
- enable if one or more cards are playing video
- disable if no cards are playing video
- Settings:
- always visible
- always enabled

- Per-card buttons:
- Play:
- visible only when camera is detected and video is not playing
- hidden otherwise
- always enabled when visible
- Stop:
- visible only when camera is detected and video is playing
- hidden otherwise
- always enabled when visible
- Snapshot:
- icon-only button
- place on the card toolbar immediately after Play/Stop
- visible only when video is playing
- hidden otherwise
- disable while snapshot save is processing
- enable when snapshot save completes (success or failure)
- onclick captures a snapshot image from the currently playing video for that card
- Expand:
- visible only when video is playing and card is collapsed
- hidden otherwise
- always enabled when visible
- Collapse:
- visible only when video is playing and card is expanded
- hidden otherwise
- always enabled when visible

- Per-card interaction:
- Card double-click:
- enabled only when that card's video is playing
- disabled when that card's video is not playing
- when enabled, toggles collapsed or expanded state (same behavior as Expand and Collapse)

- State definitions:
- Detected: card has a valid discovered camera target.
- Playing: card has active video stream playback.
- Expanded or collapsed: current visual state of the card layout.
- Expand and Collapse are mutually exclusive and only relevant while playing.

## Snapshot Save Location Policy

- Add a Settings option for snapshot save folder selection using a folder picker (`Snapshot Save Folder`).
- Persist the selected folder path in `%LocalAppData%\\LocalCam\\settings.json` and load it on startup.
- Default effective snapshot save folder is `%UserProfile%\\Pictures\\LocalCam` (shown as `Pictures` in UI when applicable).
- Effective save path rule:
- if the active folder is the user's Pictures folder, save to `%UserProfile%\\Pictures\\LocalCam`
- if the active folder is any other user-selected folder, save directly in that folder (no forced `LocalCam` subfolder)
- Create `%UserProfile%\\Pictures\\LocalCam` if it does not exist when Pictures is the active folder.
- Keep snapshot filenames unique to avoid collisions.
- Show a concise user-facing error and structured diagnostic log if the target folder is unavailable or inaccessible at save time.
