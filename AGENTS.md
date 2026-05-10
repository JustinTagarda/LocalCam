# LocalCam

## Inheritance Rule

- Always read and follow [D:\Projects\AGENTS.md](D:\Projects\AGENTS.md) first.
- This file adds reusable project rules for LocalCam and still defers to the global instructions first.

## Reusable Rules

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

## Project Specification

- See [SPECIFICATION.md](D:\Projects\LocalCam\SPECIFICATION.md) for the current project behavior, scope, and implementation-based product spec.
- Treat `AGENTS.md` as the operating/instruction file and `SPECIFICATION.md` as the product reference.
