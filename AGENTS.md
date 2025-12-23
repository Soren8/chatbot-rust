# AGENTS.md - Development Guide

## Build & Run Commands

- Run Rust integration tests: `docker compose run --rm tests cargo test`
- Run in Docker: `docker compose up --build`
- Do not attempt to build, run, or test outside of the docker environment.

## Code Style Guidelines
- **Imports**: Standard library first, then third-party, then local modules
- **Error Handling**: Use `anyhow` or `thiserror` for error handling, log errors appropriately with `tracing`
- **Dead code**: Prefer deleting unused code over commenting it out
- **History**: Do not add comments about how code used to be; use git history

## Scratchpad / Temp Files
- Use `temp/` for ephemeral notes (e.g., TODOs) — it is gitignored
- Never reference `temp/` items in commit messages
- Keep `temp/todo.md` updated as you progress

## Refactoring guidelines
- First write concise, focused integration tests that cover existing functionality if needed.
- Make sure those tests pass.
- Write new refactored code that covers all old functionality.
- Ensure the appropriate tests now pass.
- Delete the legacy code (but NEVER delete tests). Tests created during feature implementation or bug fixing are permanent artifacts.

## Bug Fixing Protocol
- When a bug is reported:
  1. Write a new test case that reproduces the bug (it should fail).
  2. Implement the fix.
  3. Run the test again to confirm it passes.

## Important Notes
- Before starting work, read `docs/design.md` and `docs/design-privacy.md` to align with the current architecture and privacy posture.
- Git commit at the completion of each full task.
- ALWAYS run `docker compose up --build -d` before running tests to allow the user to reality-check the fix in the running environment while the test suite executes.
- Do not moralize about the user's language or tone.
- Preserve the `temp/.cargo/` cache directory; do not delete it because it stores Rust build artifacts used by other agents. If it is missing, recreate it inside `temp/` (never at repo root).
- Keep Docker build caches under `temp/.docker/`; create that directory inside `temp/` when needed so the repository root stays free of sandbox artefacts.
- Store test run artifacts under `temp/test-logs/`; do not create a top-level `test-logs/` directory.
- Always validate provider configurations before committing
- Use logging (via `tracing`) instead of print statements for debugging
- When asked a question, provide the answer and then stop; do not begin modifying code or implementing changes until the user explicitly provides a "proceed" instruction.
- Treat the task as complete only after all required tests pass and your changes are committed to git.
- Update any relevant docs, checklists or todo lists at the end of a task. Only add content to docs, not checklists or todo lists.
- NEVER add cache busting mechanisms (e.g., query parameters on script tags) unless the user explicitly asks for it. Assume the user knows how to clear their cache.
