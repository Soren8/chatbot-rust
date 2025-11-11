# AGENTS.md - Development Guide

## Build & Run Commands

- Run Rust integration tests: `docker compose run --rm tests cargo test --manifest-path rust/Cargo.toml`
- Run in Docker: `docker compose up --build`
- Do not attempt to build, run, or test outside of the docker environment.

## Code Style Guidelines
- **Imports**: Standard library first, then third-party, then local modules
- **Error Handling**: Use try/except with specific exception types, log errors appropriately
- **Dead code**: Prefer deleting unused code over commenting it out
- **History**: Do not add comments about how code used to be; use git history

## Scratchpad / Temp Files
- Use `temp/` for ephemeral notes (e.g., TODOs) — it is gitignored
- Never reference `temp/` items in commit messages
- Keep `temp/todo.md` updated as you progress

## Refactoring guidelines
- First write concise, focused integration tests (in the new target language) that covers existing functionality if needed.
- Make sure those tests pass.
- Write new refactored code that covers all old functionality.
- Ensure the appropriate tests now pass.
- Delete the legacy code.

## Important Notes
- Before starting work, read `docs/design.md` and `docs/design-privacy.md` to align with the current architecture and privacy posture. Follow any in-progress refactor trail they reference (currently `docs/rust-refactor.md`).
- Git commit at the completion of each full task.
- Do not moralize about the user's language or tone.
- Preserve the `.cargo/` directory; do not delete it because it caches Rust build artifacts used by other agents.
- Always validate provider configurations before committing
- Use logging instead of print statements for debugging
- Skip running `python3 -m compileall`; it’s slow here and the user will run real functional tests.
- Treat the task as complete only after all required tests pass and your changes are committed to git.
- Update any relevant docs, checklists or todo lists at the end of a task. Only add content to docs, not checklists or todo lists.


