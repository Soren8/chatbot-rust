# Codebase review program

A seven-pass, evidence-backed review for behavior-preserving improvements—not a rewrite or a target number of findings.

## Passes and status

| Phase | File | Status | Final gate | Open items |
| --- | --- | --- | --- | --- |
| 1. Modularity — ownership and lifecycle boundaries | [modularity.md](modularity.md) | Complete for authorized scope | Full suite `20260919T202846-0908e2daba66` (commit `d55ee5d`) | MOD-001/002, 003, 006, 007, 013–017; see [modularity](modularity.md#open-items) and [findings](findings.md). No phone, vehicle or GPU runtime validation. |
| 2. Simplicity — redundant branches, copies and indirection | [simplicity.md](simplicity.md) | Complete | Full suite `20260928T080643-0e0c1b195846` (commit `40ac92f`) | No Phase 2 findings; cross-pass items remain with their owners. |
| 3. Abstractions/reuse — bounded sharing and duplication | [abstractions.md](abstractions.md) | Complete for agreed moderate scope | Full suite `20260928T225818-53da7826b56a` (completion review reaffirmed at `be18093`) | Cross-pass items remain with their owners. |
| 4. Security/privacy — security and privacy boundaries | [security.md](security.md) | Complete for reviewed scope | Full suite `20260929T043340-482ba1a11f9d` | Accepted device/topology and other boundaries; see [security](security.md#open-items) and [findings](findings.md). |
| 5. Performance/resources — measured costs and resource bounds | [performance.md](performance.md) | Complete | Full suite `20261001T052944-8b04233f9f0f` (commit `5f64c9e`) | Host proxy, device/GPU measurements and retained/deferred items; see [performance](performance.md#open-items). |
| 6. Test quality — behavior coverage, regressions and harnesses | [test-quality.md](test-quality.md) | Reopened: TEST-001 in progress | Full suite `20261002T061504-afeafe0db3d6` (commit `2412b78`; 1,167 tests) | TEST-001 (test-binary isolation) open; TQ-026 recorded only; see [test-quality](test-quality.md#findings). |
| 7. Documentation — prose and behavior-comment accuracy | [documentation.md](documentation.md) | All findings fixed; final gate pending | Pending full suite after TEST-001 | None; see [documentation](documentation.md#resolution). |

## Standing rules

- Require evidence for findings; static performance observations are leads until cost is measured where possible.
- For reported bugs, add a red-first regression, fix the behavior, then rerun the unchanged regression. Never weaken tests to pass.
- Run tests through the executor (`testctl`); do not run application suites on the host. Confirm intended tests ran.
- Host rebuilds/restarts and live rollout remain human-controlled; no live deployment is implied by review gates.
- Preserve intended behavior and compatibility; keep explicit exclusions and evidence limits. A completed pass does not claim unmeasured device, GPU, topology or live behavior.
- Docs and comments that lag the code are fixed directly; ask only when the code itself may be wrong. Completed plans are folded into living docs and deleted.

## Applying the changes

Host rebuild/restart is needed for server/static changes, the GPU voice service, and the Android app/APK where applicable. Phase-specific notes are in [performance.md](performance.md#completion) and [test-quality.md](test-quality.md#completion); host rollout is not performed by this review.
