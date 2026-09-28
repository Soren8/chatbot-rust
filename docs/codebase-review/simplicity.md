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

## Session 055 — SIM-001/002/003 implementation, 2026-09-26

Branch `refactor`. All three batches implemented with characterization-first verification; each committed separately. No application tests were modified except the two fixture harnesses below, whose assertions are retained.

**SIM-001 implemented (`088b6e0`).** Added `migration_treats_empty_legacy_file_as_single_default` (passes before and after). Merged the missing-file branches into one `mark_user_migrated_empty` outcome and collapsed default insertion to a single `!any(is_default)` push with an invariant comment (`list_sets` always yields the default entry; a `"default"`-named import already carries the flag). Core lib: 182/182 exit 0 (`sim1-migration-green-20260926.log`).

**SIM-002 implemented (`0804aee`).** Added `xai_search_without_brave_key_and_without_fallback_is_fail_closed` unit test pinning the `PrivacyRestrictedFallback` decision with no network (passes before and after). Flattened the XAI arm: fail-closed no-brave case returns early via `use_brave`, adapter-construction and search-setup failures share one `fallback_or_restricted` owner, distinct warnings retained, one structurally required clone kept at the by-value search call. Verified: new unit test, `generation_dispatch` 15/15, `search` 5/5, `privacy_policy` 8/8, all exit 0.

**SIM-003 implemented (`ffae261`).** Caller trace: `validateModelTier` refreshed after its own visibility sync already refreshed, and ready-init called the bare refresh immediately before the same sync. Removed both redundant calls; `disablePremiumModels` stays as the fixture-pinned definition. Repaired two drifted fixtures with real owners (no assertion weakened): request-application evaluates the real eligibility chain (`currentSetId`, `loadedPrivacy`–`canSubmitChat`) with an eligible model plus per-switch policy seeding, and stubs only the leaf DOM projection; playback-vm evaluates the real voice-binding helpers over a real history window plus the real guest voice-readiness gate, and mirrors the click path's binding capture. `conversation_request_application`, `conversation_request_binding`, `js_syntax` 11/11, `desktop_playback_cancellation` 5/5 and `desktop_playback_cancellation_vm` 7/7 all exit 0.

**Full-suite gate blocked by pre-existing main drift.** `simplicity-full2-20260926.log`: 52 targets pass, then `generation_error_ownership` fails (`chat_upstream_500...` gets 403, expects 200). The mock HTTP provider is privacy-ineligible for the default-Private set, a main-side privacy-stage/test drift predating this work; reproduced identically on pristine main `f7b008f` via worktree (`main-baseline-gen-err-20260926.log`). Repairing it is a product-contract decision (eligible test world vs enforcement), not a simplicity change, and is left for explicit scope authorization. Targets alphabetically after it remain unverified in the full run.

## Session 056 — review fixes and full-suite green, 2026-09-27

Branch `refactor`. Implemented the primary review's required corrections, each committed separately with targeted verification:

- **Fallback coverage.** Added direct `fallback_or_restricted` tests for both outcomes (allowed yields a lazily-built stream with no network; denied yields `PrivacyRestrictedFallback`) plus a code comment documenting the two dispatch-level setup-error arms as defensive (provider construction fails only on HTTP-client setup; search errors surface at poll time, not at dispatch).
- **Blocked eligibility.** Added `blocked-send`, `blocked-regen` and `switch-load` scenarios exercising the real gate with no loaded policy, including a switch before the new set's policy arrives; all prior assertions retained.
- **Fixture-only wrapper.** Removed `disablePremiumModels` from production; re-anchored the playback slice on the retained `validateModelTier` assignment.
- **Full-suite drift.** Classified controlled mock providers as `private` in `generation_error_ownership`, `prepare_policy_boundary` and the `provider_config_isolation` YAML configs (production enforcement unchanged); restored the missing-set saved-turn contract in the chat/regenerate privacy pre-checks; sent the data key in the login CSRF isolation probes so the 400/401 signal is not masked by the per-request key gate. Every drift repair was reproduced on pristine main first via worktree or stash.

Final full suite `temp/test-logs/fixes-full5-20260927.log`: job `20260927T034301-3820e47af13a`, exit 0, untruncated, 121 targets ok, zero failures. No Android changes, so no APK rebuild was required.

Note: `temp/test-logs/` was emptied by an external cleanup mid-session; earlier per-batch logs survive only as job IDs recorded here. Final evidence above is intact.

## Expanded phase-two scope

The primary reviewer will inspect current handwritten implementation and relevant callers across Rust core/server, first-party browser code, Android, Python voice service, DNS, and build/deployment integration. Include additions since phase one, particularly privacy, external connections and server selection. Update file-level coverage at the current revision rather than inheriting modularity coverage as simplicity credit.

Look for redundant branches, unreachable states, unnecessary conversions/copies, misleading wrappers, speculative helpers and indirection that makes execution harder to understand. Do not use line count or a target number of deletions as the objective. Preserve ownership boundaries established in phase one, explicit error precedence, lazy configuration semantics, compatibility requirements, migration support and desktop/native policy parity. Public compatibility surfaces need an explicit consumer/contract assessment before deletion.

Generated/vendor/binary/protected material receives boundary-only coverage with exclusions recorded. Test bodies are inspected as needed for simplification contracts; this does not complete the separate test-quality audit. Later-pass correctness/security/performance findings, including Auto protocol repair, native key export and COR-003, retain their deferrals unless directly necessary to an approved simplicity change.

## Session 057 — fresh repository-wide simplicity inventory, 2026-09-28

Branch `refactor@847e4cc` (clean). Four parallel research-only workers inventoried handwritten code across core, server, browser, and Android/Python/DNS/build; the primary reviewer then traced each high-confidence candidate to its callers before approval. All four batches below are implemented (SIM-004–007, commits after this section) with targeted green verification; the full-suite gate follows.

### Session 057 verification

Targeted (all exit 0): `js_syntax` 11/11; `conversation_request_application` 1/1; `conversation_request_binding` 1/1; `conversation_state` 11/11; `desktop_playback_cancellation` 5/5; `desktop_playback_cancellation_vm` 7/7; `generation_dispatch` 15/15; `search` 5/5; `privacy_policy` 8/8; `provider_config_isolation` 23/23; `voice_privacy` 9/9; `tts` 15/15; `voice_service_lifecycle` 1/1; core lib 182/182; `home` 8/8; `generation_error_ownership` 4/4; `router_identity_isolation` 6/6; `static_assets` 15/15; `set_privacy` 1/1; DNS `unittest discover` 31/31.

Final full suite `temp/test-logs/sim57-full-20260928.log`: job `20260928T054654-a257a7ed62e5`, exit 0, untruncated, 121 suites ok / 991 passed / 0 failed, including provider configuration checks. Primary review corrections applied before the run: migration rename keeps a graceful no-parent path (no new panic), dev-override keeps its trailing newline, the model-select comment names the visibility sync, and `config_source` notes the `from_providers` mirror. No Android changes (no APK rebuild); no browser-visible or template changes (no preview verification needed beyond the JS suites).

### Approved for bounded implementation (primary-verified)

**Core batch (SIM-004).**
- `session_identity.rs:92-95,124-144,188-225` — `clean_expired` (retain `<= timeout`) runs under the same lock and `Instant` immediately before `ensure_record`/`validate_csrf_token`, so the second expiry branches are unreachable via the only two `ensure_record` callers (`prepare_home_context`, `session_context`) and the CSRF path. Bounded: drop the dead branches, keep purge + lookup/update. Characterization: `chatbot-core/tests/http_identity_isolation.rs`. High.
- `config_source.rs:87-98` — global `destination_policy` clones full `ProviderConfig` values into a temp `Vec` only to read name + level in `from_providers`. `provider()` returns `Option<&ProviderConfig>` (`config.rs:277`), so the clones are avoidable. Bounded: build the map from borrowed providers without changing `from_providers` semantics or call-time live reads. Characterization: `privacy_policy.rs`. High.
- `history/ops.rs:201-206` — `derive_chat_name_from_message` joins all whitespace-collapsed words then re-splits to take 6. Bounded: take 6 words directly from the stripped text; keep truncation/sanitization. Callers `history/api.rs:715,751`. High.
- `history/migration.rs:127-131` — `rename_legacy_sets_json` `parent() == None` fallback is unreachable: `sets_json_path` always yields `{root}/user_sets/{user}/sets.json` (`legacy_sets_json/store.rs:125-127`). Bounded: join the backup name through the known parent. Characterization: migration idempotency tests. High.

**Server batch (SIM-005).**
- `providers/generation.rs:162` — OpenAI no-Brave arm clones `messages` for a by-value `stream_chat` with no fallback. Bounded: move the vector in that arm only; keep clones in Brave/fallback arms. Characterization: `search.rs`, `generation_dispatch.rs`. High.
- `generation_deps.rs:196-202` — `owned_provider_summaries` collects keys from `owned.providers` then re-gets each with an impossible `None` continue (no mutation between). Bounded: iterate entries directly, keep sort order + tier filter. Characterization: `provider_config_isolation.rs`, `home.rs`. High.
- `tts/store.rs:150-155` + `tts.rs:284-328` — `snapshot()` clones the destination on every call, but the snapshot destination is never consumed: the `Begin` arm uses `begin()`'s destination and the `Cached` arm returns before touching it. Bounded: snapshot the binding only; keep coordinator-before-map ordering and permit acquisition. Characterization: TTS/voice-privacy tests. High.

**Browser batch (SIM-006).**
- `static/chat.js:3113,3265` — `loadedPrivacy` stores `version` on save/load but no reader uses it (all readers use `setId`/`level`; CAS uses `APP_DATA.setVersion`). Bounded: stop storing the dead field. Characterization: `conversation_request_application_test.js` blocked-policy scenarios. High.
- `static/chat.js:2696-2704` — render-markdown handler iterates `.ai-message` building two unused selections before the `set-selector` reload that does the real work. Bounded: drop the inert iteration, keep the reload. No direct coverage found; `js_syntax` parse + targeted suite. High.
- `static/chat.js:1193-1195,2683,2715` — `validateModelTier` is a pure alias for `updateSearchToggleVisibility` (which already ends in `refreshPrivacyControls`); the name misleads (no tier check). Bounded: call the real function at both sites, remove the alias, re-anchor the playback-VM slice on the retained definition. Characterization: `desktop_playback_cancellation_vm_test.js` (slice boundary only). High.
- `static/conversation-state.js:247-265` — after `isLiveConversationBinding`/`isLiveSetBinding` establishes `binding.setId == currentSetId`, each function compares `data.set_id` against both. Bounded: keep one comparison per function. Characterization: `conversation_state_test.js`, `conversation_request_binding_test.js`. High.
- `static/tts-playback.js:182-183` — `playOne` reads `getAbortSignal()` then `void signal`; `fetchClip` acquires its own signal. Bounded: drop the unused read. Characterization: `desktop_playback_cancellation_test.js`. High.

**Infra/Python batch (SIM-007).**
- `chatbot-cuda/src/audio_utils.py:40-68` — `wav_bytes_to_array`, `numpy_to_pcm16`, `numpy_to_wav_bytes` have zero repo-wide callers (STT uses `webm_to_wav_bytes`; TTS PCM uses `service.py`). Bounded: delete the three helpers after confirming no external import contract. No direct helper coverage found; voice lifecycle tests cover the live paths. Medium-high.
- `dns/forwarder.py:294-304` — `_recvn` re-sums chunk lengths twice per loop iteration. Bounded: track remaining bytes; keep short-read/empty behavior. Characterization: `dns/tests/test_forwarder.py`. High.
- `.github/workflows/docker-build-push.yml:58-60` — `Get short SHA` step output has no consumer; `Prepare tags` recomputes the same SHA. Bounded: remove the unused step. Coverage: workflow execution. High.
- `deploy/compose/docker-compose.dev.override.yml:6-11` — dev override restates `RUST_BUILD_PROFILE: debug`, `LOG_FORMAT: plain`, `LOG_ANSI: true` already defaulted in `docker-compose.yml:47,85-86`. Bounded: drop only the redundant keys; keep `LOG_LEVEL`/purge-interval. Coverage: compose review. High.

### Investigated, no change approved

- `chat.rs`/`regenerate.rs` privacy-binding + generation-eligibility duplication (two-handler shared extraction): real duplication, but touches prepare-error precedence and lease ownership across both dispatch callers; needs deeper tracing than a simplicity batch allows. Deferred with no change.
- `chat.rs`/`regenerate.rs` stream-setup clones for finalization/guard: ownership/drop interaction unproven; deferred.
- `agent_connections.rs` double `verify` via `credentials`: needs concurrent-revision tracing; deferred.
- `credential-metadata.js` multi-pass filter: correct but algorithmic rewrite for marginal clarity; deferred.
- `static/templates/chat.html:78-83` desktop/mobile tier spans: responsive-visibility duplication is intentional; single-label rework needs visual preview for marginal gain; deferred.
- Android URL resolution + `ServerUrlSetting.executeSwitch` purge indirection + voice `start.sh`/`settings.py` dual parsing: need runtime/exception tracing and flavor APK builds; deferred (no native changes this pass, no APK required).
- `memory_snippet`/`with_version` (no production consumers found), `session.rs` compat surface, home/login CSRF probe ordering: public/compat contract assessment incomplete; no deletion without consumer-by-consumer case.
- COR-003, Auto protocol repair, native key export, security/performance-only items: retain existing deferrals.

Exclusions: `static/deps/*` (vendored), generated/vendor/binary, `node_modules/`, `target/`, `temp/`, `data/`, `.git/` — boundary-only or uninspected as noted per worker.
