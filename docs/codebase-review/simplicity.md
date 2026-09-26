# Simplicity pass

## Session 054 — primary review of the initial batch

Evidence revision: `8bca512`. Phase 2 is reopened following the user's request to review the smaller model's work and expand scope as needed. This is a review of that batch and an expanded scope definition, not completion of a fresh whole-repository pass.

### Findings about the delivered work

**P1 — Completion gate was incorrectly reported as satisfied.** `simplicity-full-20260926.log` ends at the failed `conversation_request_application` target (executor job `20260926T204516-07f8f1a170bf`, exit 101). Cargo did not run the remaining targets. “Green except one failure” therefore overstates the evidence. The baseline job `20260926T204759-7dca14050ca0` establishes a pre-existing failure, not a passing completion gate. Phase closure requires a complete passing run.

**P2 — Scope was too narrow to establish simplicity-pass completion.** The user's known-leads-only choice explains the small batch. It provides no independent simplicity coverage of the application, and the coverage ledger was not advanced. The original seven-pass program examines control flow, state and indirection as well as unused code. The expanded scope below supersedes the known-leads-only restriction.

**Accepted — The three deletions are sound.** `legacy_sets_json/mod.rs` declares only `store`; the deleted `migrate.rs` was not compiled. The permanent migration remains in `history/migration.rs`, called through `HistoryService`. `parse_chunk_key` had no caller and belonged to the private storage implementation; live encoding/range helpers remain. `chatbot-server/src/lib.rs` declares `mod providers`, so deleting the unused `openai::messages` re-export does not remove an externally reachable crate API. The shared DTO and its serialization remain intact. The retained targeted results establish 181 core library, 16 helper-contract, four provider-message and 15 generation-dispatch tests passing. No new runtime result is claimed by this review.

## Initial simplicity candidates

These are source-supported candidates for bounded implementation after adequate existing characterization is confirmed. They are not implemented fixes.

### SIM-001 — Redundant migration decision paths

Priority P2; confidence high; disposition confirmed by source. In `chatbot-core/src/history/migration.rs::ensure_user_migrated`, the missing-`sets.json` path checks whether a backup exists, but both branches call `mark_user_migrated_empty` and return. The backup check adds a decision without changing the outcome.

The import loop assigns `is_default = name == "default"`. Later, after establishing that no import has `is_default`, the code searches for an import whose display name is `default`: that success branch is unreachable under the constructor above. Both the empty-import case and the missing-default case construct the same empty default record.

Bounded correction: express the missing-file outcome once and default insertion once. Preserve migration locking/recheck, wrong-key errors, import transaction, IDs/timestamps, backup retention and post-import rename behavior. Verify existing new-user, backup-without-flag, encrypted/split-file and idempotency cases; add missing characterization for empty and non-default-only imports before changing the branches. COR-003 read-transaction consistency is separate.

### SIM-002 — Repeated XAI fallback policy in nested error branches

Priority P2; confidence high for duplication, not an asserted defect; disposition confirmed by source. `chatbot-server/src/providers/generation.rs::dispatch_stream` nests OpenAI-compatible adapter construction and Brave setup, then repeats the same `allow_native_search_fallback` decision in both error arms. It also clones owned messages at terminal calls.

Bounded correction: make setup outcomes and the final fallback decision easier to follow without introducing a generic provider framework. Preserve lazy client/config access, distinct warning messages, setup-only fallback, streaming-error behavior, native-search arguments, and fail-closed privacy decisions. Do not consolidate by dispatching before authorization. Check `generation_dispatch`, provider isolation, search and privacy tests; establish actual setup-failure coverage before modifying control flow. Clone removal is an ownership simplification, not a measured performance claim.

### SIM-003 — Browser eligibility/control refresh requires further tracing

Priority P2 candidate; disposition needs investigation. `static/chat.js:1124–1219` mixes pure level comparison, selected-model lookup, DOM state and control updates. `validateModelTier` calls `updateSearchToggleVisibility`, which already refreshes privacy controls, and then refreshes them again. The similarly named `disablePremiumModels` is now an alias for a much broader refresh. Trace all callers and initialization/set-switch ordering before removing any call or wrapper; repeated execution alone is not proof of a defect.

The request-application fixture evaluates explicit source slices that omit the newly called `canSubmitChat`. Its initial application data also lacks the new model/policy inputs. Repairing that integration fixture is a phase-completion prerequisite: exercise real eligibility with explicit valid/blocked inputs and retain all stale-response, cancellation, replacement and autoplay assertions. An unconditional `canSubmitChat = () => true` would bypass the new behavior rather than establish the composed contract. Broader fixture replacement remains the test-quality pass.

## Expanded phase-two scope

The primary reviewer will inspect current handwritten implementation and relevant callers across Rust core/server, first-party browser code, Android, Python voice service, DNS, and build/deployment integration. Include additions since phase one, particularly privacy, external connections and server selection. Update file-level coverage at the current revision rather than inheriting modularity coverage as simplicity credit.

Look for redundant branches, unreachable states, unnecessary conversions/copies, misleading wrappers, speculative helpers and indirection that makes execution harder to understand. Do not use line count or a target number of deletions as the objective. Preserve ownership boundaries established in phase one, explicit error precedence, lazy configuration semantics, compatibility requirements, migration support and desktop/native policy parity. Public compatibility surfaces need an explicit consumer/contract assessment before deletion.

Generated/vendor/binary/protected material receives boundary-only coverage with exclusions recorded. Test bodies are inspected as needed for simplification contracts; this does not complete the separate test-quality audit. Later-pass correctness/security/performance findings, including Auto protocol repair, native key export and COR-003, retain their deferrals unless directly necessary to an approved simplicity change.

Use bounded batches with existing green behavioral characterization before restructuring and unchanged failing regressions for bug fixes. Workers may implement prepared batches; the primary reviewer owns initial source review and acceptance. Keep targeted executor logs during development, validate provider configuration before application commits, and obtain a full green executor run on the final implementation. Native changes require the trusted APK build; browser-visible changes require appropriate preview verification. Final primary review must account for every finding and coverage exclusion before declaring phase 2 ready for completion review.
