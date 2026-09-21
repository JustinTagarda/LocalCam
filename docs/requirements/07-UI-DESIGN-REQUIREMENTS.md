# LocalCam UI Design Requirements

Status: Current implementation baseline

## Global button baseline

`App.xaml` owns `GlobalButtonStyle`, and the implicit `Button` style is based on it. All buttons across the application must use that style directly or use a specialized style whose inheritance chain reaches `GlobalButtonStyle`.

## Camera-area action buttons

The action buttons inside each camera area's in-video overlay are a scoped exception to the global button sizing baseline:

- Owning implementation: `MainWindow.xaml`, `CameraOverlayIconButtonStyle`.
- Applies only to camera-area in-video action buttons: Expand, Collapse, Play, Stop Stream, Snapshot, and Record.
- Width must remain content-sized: do not set a fixed `Width`; set `MinWidth` to `0` so the global `MinWidth` does not force a wider button.
- Height must remain automatic: do not set a fixed `Height`.
- Padding must remain uniform `6px` on all sides.
- Every action icon must use a `16x16` content canvas. Inner glyphs may retain their visual proportions within that canvas.
- Existing icon content, visibility, enablement, tooltips, commands, margins, overlay placement, and accessibility behavior must remain unchanged.
- The style must continue to derive from `GlobalButtonStyle` so global theme resources, cursor behavior, and shared interaction behavior remain available.
- This sizing rule must not be copied to toolbar, Settings, dialog, update, status, or other non-camera buttons.

## Strict guardrails

- Do not add a fixed width or height to `CameraOverlayIconButtonStyle` or to the code-created camera action buttons without explicit approval.
- Do not change the camera-area action-button padding from uniform `6px` without explicit approval.
- Do not introduce an action icon with a content canvas other than `16x16` without explicit approval.
- Do not resize the inner glyphs merely to fill the canvas; preserve recognizable proportions unless a separate visual design change is approved.
- Do not change `GlobalButtonStyle` sizing to solve a camera-area layout issue; use the camera-specific derived style only.
- Do not create a second camera button style or independent button template.
- Any future camera-area button sizing change must update this document, the traceability verification steps, and the durable decision/constraint record together.
- Verify the buttons in collapsed and expanded cards during active playback, including resize, DPI scaling, and System/Light/Dark theme changes.
