# Workspaces, Repositories and GitHub

Filesystem resources for agents: persistent per-user workspaces, repositories
and worktrees inside them, GitHub identity, scoped credentials, and turn-level
snapshots and undo.

## 1. Workspace

A workspace is a persistent volume plus a runner image profile, owned by one
user and independent of any conversation. Threads attach to a workspace (and a
worktree inside it); several threads may share a workspace.

```rust
struct Workspace {
    id: WorkspaceId,
    owner: UserId,
    name: String,
    privacy: PrivacyLevel,              // fixed at creation (architecture.md §5.2)
    image: RunnerImageRef,              // operator-curated images: base, rust, node, python, android
    resources: ResourceProfile,         // cpu, memory, pids, disk quota
    network: NetworkPolicy,             // default for sandboxed commands (tools.md §7.3)
    repositories: Vec<RepositoryId>,
    status: WorkspaceStatus,            // provisioning | stopped | starting | running | degraded | failed | deleting
    created_at: Timestamp,
    last_active_at: Timestamp,
}
```

Volume layout inside the runner:

```
/work/
  repos/<repo-slug>/                 bare-ish main clone (.git + default branch checkout)
  worktrees/<repo-slug>/<worktree>/  git worktrees, one per task branch
  scratch/                           non-repository files
  .agent/                            runner state: journal, snapshots index, harness homes
     harness/<kind>/home/            per-harness HOME (vendor logins live here)
/home/agent/                         user's shell home (dotfiles, caches), persistent
/tmp                                 tmpfs, per-runner boot
```

Workspace metadata is stored in the control plane (plaintext index plus sealed
fields for names); the volume itself lives on the agent host.

### 1.1 Lifecycle

| Action | API | Effect |
|---|---|---|
| Create | `POST /workspaces {name, privacy, image, resources?}` | record + `EnsureRunner` (lazily, on first use) |
| Start / stop | `POST /workspaces/{id}/start`, `/stop` | `EnsureRunner` / `StopRunner` |
| Delete | `DELETE /workspaces/{id}` with a typed confirmation of the name | refuse while threads are running; `DeleteWorkspace`; threads keep their history and show the workspace as deleted |
| Status | `GET /workspaces/{id}` | runner status, disk usage, repositories, worktrees |

Runners start on demand when a turn needs a tool, a terminal is opened, or a
harness is started, and stop after 30 minutes idle (architecture.md §1.3).

### 1.2 Quotas

Per user: workspace count (default 3), disk per workspace (default 20 GiB),
concurrent running runners (default 2). Quotas are enforced by the workspace
manager; the control plane checks them first for good error messages.

## 2. Repositories

```rust
struct Repository {
    id: RepositoryId,
    workspace_id: WorkspaceId,
    slug: String,                       // directory name
    remote: Option<RemoteRef>,          // { provider: github | generic_https | none, url, owner, name, connection_id? }
    default_branch: String,
    trust: TrustLevel,                  // untrusted (default) | trusted (agent-loop.md §11.3)
    visibility: Option<RepoVisibility>, // public | private, refreshed from GitHub
}
```

Operations (`POST /workspaces/{id}/repositories`):

- `clone {url | github: {owner, name}, branch?}` — clone through `GitOp` with a
  read token if private.
- `init {slug}` — empty repository.
- `import {upload_id}` — tarball upload for repositories without a remote.

Clones are partial (`--filter=blob:none`) by default.

## 3. Worktrees

Each agent task works in its own worktree so concurrent threads do not fight
over one checkout. This mirrors how Codex cloud tasks and the Codex desktop app
isolate tasks.

```rust
struct Worktree {
    id: WorktreeId,
    repository_id: RepositoryId,
    path: RunnerPath,                   // /work/worktrees/<slug>/<name>
    branch: String,                     // agent/<thread-short-id>-<slug> by default
    base: GitRef,                       // branch + commit it started from
    thread_ids: Vec<ThreadId>,
    status: WorktreeStatus,             // active | merged | abandoned
}
```

- Creating a thread with `workspace: {repository, worktree: "new"}` creates a
  worktree from the default branch (or a given base).
- `worktree: "main"` attaches to the main clone (for chores the user wants on
  the main checkout); only one running thread may hold a write lease on a
  checkout at a time. A second writer gets `409 worktree_busy` and may choose
  read-only or a new worktree.
- Cleanup: worktrees of merged branches are removed after 7 days; abandoned
  worktrees are listed in the workspace view for manual deletion.

## 4. GitHub connections and credentials

### 4.1 Connection types

| Type | Use | Credential stored |
|---|---|---|
| **GitHub App** (recommended) | Operator registers one app; each user installs it on the accounts/repositories they choose | installation id per user; the app private key is operator config |
| **OAuth app / user token** | Acting as the user (PRs authored by the user, private repos the app is not installed on) | user-to-server refresh token, sealed with the user's data key |
| **Fine-grained PAT** | Fallback for self-hosters without an app | the token, sealed with the user's data key |

Connection records extend the existing agent-connection pattern
(`agent_connections.rs`): per-user, sealed, AAD-bound, CRUD under
`/github_connections`, with a `check` route that calls `GET /user` or
`GET /installation/repositories` only.

### 4.2 Token broker

The control plane mints tokens per operation and never stores minted tokens:

- GitHub App: `POST /app/installations/{id}/access_tokens` with
  `repositories: [name]` and the minimal `permissions` for the op
  (`contents: read` for clone/fetch, `contents: write` for push,
  `pull_requests: write` for PR creation). Tokens live ≤ 1 hour; the broker
  requests them just in time.
- OAuth tokens are refreshed in the control plane when the user's key is
  present. For `Attended` custody this means GitHub push from an unattended run
  waits for the user (status `awaiting_key`); `RunKey` custody wraps the
  refresh token under the run key for the duration of the run.

### 4.3 Operations

`GitOp { op, token_ref }` from the control plane to the runner:

| `op` | Permission | Approval |
|---|---|---|
| `Clone { url, dest, branch?, filter }` | contents:read | none |
| `Fetch { repo }` | contents:read | none |
| `Push { worktree, remote_branch, force: false }` | contents:write | ask unless the thread's profile pre-approves pushes to `agent/*` branches |
| `Push { force: true }` | contents:write | always ask |
| `CreatePullRequest { worktree, base, title, body, draft }` | executed by the control plane against the GitHub API, not by the runner | ask (publication) |

Pushing to a public repository is a publication event and is checked against
thread privacy (architecture.md §5.1): a `private` thread cannot push to a
public repository.

### 4.4 Git credential helper

Model-run commands (`git push` typed by the agent) must not see tokens.

- The runner installs `git-credential-agent` as the credential helper for
  `https://github.com` in its system gitconfig.
- The helper talks to the runner over a Unix socket that is **not** mounted in
  the inner sandbox (tools.md §7.2). Commands inside the sandbox therefore get
  no credentials: `git push` from `exec_command` fails with an authentication
  error. The model is instructed (base prompt) to use the `git_push` and
  `create_pull_request` tools instead.
- `git_push {remote_branch?, force?}` and `create_pull_request {title, body,
  base?, draft?}` are tools registered when the workspace repository has a
  GitHub connection. They go through approval (§4.3) and then `GitOp`.
- For `GitOp`, the runner runs git outside the inner sandbox with the helper
  socket available; the helper answers only for the repository URL in the
  current `GitOp` and only with the token delivered with it, then forgets it.
- Harnesses that push by themselves (Claude Code, Codex) run with the same
  helper available only when the user enables "harness may push" for that
  thread; otherwise the helper denies requests from harness process trees.

### 4.5 SSH and other remotes

SSH remotes are not supported for agent-initiated operations in phase 1.
Generic HTTPS remotes with a user-provided token use the same broker path with
the token sealed per connection.

## 5. Snapshots and undo

### 5.1 Turn snapshots

At turn start (before the first mutating tool call) the runner records a
snapshot of each attached worktree:

```text
snapshot(worktree):
    tree = git write-tree using a temporary index:
        GIT_INDEX_FILE=.agent/tmp-index git add -A (respecting .gitignore)
        git write-tree
    commit = git commit-tree tree -p HEAD -m "agent snapshot <thread>/<turn>"
    git update-ref refs/agent/snapshots/<thread>/<turn> commit
```

This is the Codex "ghost commit" approach: snapshots never touch the user's
index, branch or stash, and untracked non-ignored files are included. Files
larger than 10 MiB and ignored paths are excluded and listed in the snapshot
record as `not_restorable`.

### 5.2 Undo

`POST /threads/{id}/turns/{turn_id}/undo` restores the worktree to the
snapshot taken at the start of that turn:

1. Refuse if a turn is running.
2. Compute the paths changed since the snapshot; show them for confirmation
   (UI) — the request carries the confirmed path list hash.
3. `git read-tree` + `git checkout-index` from the snapshot for tracked paths;
   delete files that did not exist in the snapshot; leave `not_restorable`
   paths untouched and report them.
4. Record an `Undo` notice item; the model sees a developer message on the next
   turn that the worktree was reverted to before turn N.

Undo does not rewrite git history the agent created with commits; it restores
working-tree content. Reverting commits is a normal git action.

Snapshot refs older than 14 days or beyond the latest 50 per thread are pruned.

### 5.3 Fork

Forking a thread at a turn (`events-and-storage.md` §6.1) creates a new
worktree from that turn's start snapshot, on a new branch, so the fork can
diverge without affecting the original.

### 5.4 Turn diff

The final turn diff (agent-loop.md §2.5) is `git diff <turn-start snapshot>`
against a fresh snapshot at turn end, which captures edits made by shell
commands as well as by `apply_patch`.

## 6. Context files from the workspace

`ReadContextFiles` (architecture.md §3.1) returns for the cwd:

- the project root (nearest `.git` ancestor) and repository identity;
- the `AGENTS.md` chain (agent-loop.md §6.2);
- skills under `.agents/skills/` (agent-loop.md §6.3);
- trusted repository config, roles, rules, hooks and MCP config, only when the
  repository is trusted;
- git status summary: branch, ahead/behind, dirty file count.
