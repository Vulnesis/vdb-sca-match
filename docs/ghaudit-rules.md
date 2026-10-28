# Vulnetix GitHub posture rules

Generated from `ghaudit` — do not edit by hand; run `go test ./ghaudit -run TestCatalogueDoc -update`.

Rules marked *needs* only run when those facts were collected (via the GitHub API or the GitHub App); without them they are reported as not evaluated rather than passed. Rules marked *uses* run on files alone and use the facts, when present, to lower severity where a setting removes the risk and raise it where a setting makes it worse.

## Workflows — `vulnetix gha workflows`

| ID | Rule | Severity | CWE | Context |
|---|---|---|---|---|
| [VNX-GH-001](#vnx-gh-001) | Untrusted input expanded into an executed script | critical | CWE-94, CWE-78 | uses repo |
| [VNX-GH-002](#vnx-gh-002) | Untrusted input written to GITHUB_ENV or GITHUB_PATH | high | CWE-77, CWE-427 |  |
| [VNX-GH-003](#vnx-gh-003) | Privileged workflow runs code from an untrusted pull request | critical | CWE-829, CWE-94 | uses repo, environments |
| [VNX-GH-004](#vnx-gh-004) | Checkout credentials persisted into an uploaded workspace | high | CWE-522, CWE-200 |  |
| [VNX-GH-005](#vnx-gh-005) | Privileged workflow consumes artifacts from an untrusted run | high | CWE-494, CWE-345 |  |
| [VNX-GH-006](#vnx-gh-006) | Release workflow restores a cache writable by untrusted runs | high | CWE-349, CWE-494 |  |
| [VNX-GH-007](#vnx-gh-007) | Workflow token permissions not declared | medium | CWE-250, CWE-272 | uses repo |
| [VNX-GH-008](#vnx-gh-008) | Excessive token permissions | medium | CWE-250, CWE-732 |  |
| [VNX-GH-009](#vnx-gh-009) | OIDC token minted outside a protected environment | medium | CWE-285, CWE-863 | uses environments |
| [VNX-GH-010](#vnx-gh-010) | All secrets passed to a reusable workflow | medium | CWE-200, CWE-668 | uses repo |
| [VNX-GH-011](#vnx-gh-011) | Secrets context exposed in bulk | high | CWE-200, CWE-532 |  |
| [VNX-GH-012](#vnx-gh-012) | Hard-coded container registry credentials | high | CWE-798 |  |
| [VNX-GH-013](#vnx-gh-013) | Deprecated workflow commands re-enabled | high | CWE-77 |  |
| [VNX-GH-014](#vnx-gh-014) | Authorisation by spoofable actor name | high | CWE-290, CWE-863 |  |
| [VNX-GH-015](#vnx-gh-015) | Condition always evaluates to true | high | CWE-570, CWE-571, CWE-697 |  |
| [VNX-GH-016](#vnx-gh-016) | Self-hosted runner reachable from pull requests | high | CWE-829, CWE-668 | uses repo, runner_groups |
| [VNX-GH-017](#vnx-gh-017) | Secret printed to the job log | medium | CWE-532 |  |
| [VNX-GH-018](#vnx-gh-018) | Comment-triggered workflow without an author check | high | CWE-862, CWE-863 | uses repo |
| [VNX-GH-019](#vnx-gh-019) | Obfuscated action reference or expression | low | CWE-656 |  |
| [VNX-GH-020](#vnx-gh-020) | Pull request head ref used as a branch or tag name without quoting | medium | CWE-88 |  |

## Actions and images — `vulnetix gha actions`

| ID | Rule | Severity | CWE | Context |
|---|---|---|---|---|
| [VNX-GH-101](#vnx-gh-101) | Action or reusable workflow not pinned to a commit SHA | medium | CWE-829, CWE-494 | uses action_refs, actions_policy, repo |
| [VNX-GH-102](#vnx-gh-102) | SHA pin does not match its version comment | high | CWE-345, CWE-451 | needs action_refs |
| [VNX-GH-103](#vnx-gh-103) | Pinned commit is not in the action's repository | critical | CWE-345, CWE-494 | needs action_refs |
| [VNX-GH-104](#vnx-gh-104) | Action repository archived, missing or hijackable | high | CWE-1104, CWE-494 | needs action_refs |
| [VNX-GH-105](#vnx-gh-105) | Action version has a published vulnerability | high | CWE-1395 | needs action_refs |
| [VNX-GH-106](#vnx-gh-106) | Container image not pinned to a digest | low | CWE-829, CWE-494 |  |
| [VNX-GH-107](#vnx-gh-107) | Action major version runs on a retired runtime | low | CWE-1104 |  |
| [VNX-GH-108](#vnx-gh-108) | Action not permitted by the allowed-actions policy | medium | CWE-284 | needs actions_policy |
| [VNX-GH-109](#vnx-gh-109) | Action owner resembles a popular publisher | high | CWE-1357 |  |
| [VNX-GH-111](#vnx-gh-111) | Remote script piped into an interpreter | medium | CWE-494, CWE-829 |  |

## Repository settings — `vulnetix gha settings`

| ID | Rule | Severity | CWE | Context |
|---|---|---|---|---|
| [VNX-GH-201](#vnx-gh-201) | Default branch is not protected | high | CWE-284, CWE-862 | needs repo, branches |
| [VNX-GH-202](#vnx-gh-202) | Default branch merges without review | high | CWE-862 | needs repo, branches |
| [VNX-GH-203](#vnx-gh-203) | Approvals survive new commits | medium | CWE-862 | needs repo, branches |
| [VNX-GH-204](#vnx-gh-204) | Workflow changes bypass code owners | medium | CWE-862 | needs repo, branches, codeowners |
| [VNX-GH-205](#vnx-gh-205) | Force pushes or deletion allowed on the default branch | high | CWE-284 | needs repo, branches |
| [VNX-GH-206](#vnx-gh-206) | Branch protection can be bypassed | medium | CWE-284, CWE-863 | needs repo, branches |
| [VNX-GH-207](#vnx-gh-207) | No required status checks | low | CWE-754 | needs repo, branches |
| [VNX-GH-208](#vnx-gh-208) | Workflow token defaults to write | medium | CWE-250, CWE-276 | needs repo, actions_policy |
| [VNX-GH-209](#vnx-gh-209) | GitHub Actions can approve pull requests | medium | CWE-862 | needs repo, actions_policy |
| [VNX-GH-210](#vnx-gh-210) | Fork pull request workflows run without approval | medium | CWE-862 | needs repo, actions_policy |
| [VNX-GH-211](#vnx-gh-211) | Any action may run | low | CWE-829 | needs repo, actions_policy |
| [VNX-GH-212](#vnx-gh-212) | Secret scanning or push protection disabled | medium | CWE-798 | needs repo, security_and_analysis |
| [VNX-GH-213](#vnx-gh-213) | Dependabot security updates disabled | low | CWE-1104 | needs repo, security_and_analysis |
| [VNX-GH-214](#vnx-gh-214) | Environment secrets deployable without approval | high | CWE-284, CWE-862 | needs repo, environments |
| [VNX-GH-215](#vnx-gh-215) | Deploy key with write access | medium | CWE-732 | needs deploy_keys |
| [VNX-GH-216](#vnx-gh-216) | Webhook deliveries can be forged or intercepted | medium | CWE-345, CWE-295 | needs webhooks |
| [VNX-GH-217](#vnx-gh-217) | Outside collaborator with admin access | medium | CWE-269 | needs collaborators |
| [VNX-GH-218](#vnx-gh-218) | Signed commits not required | low | CWE-345 | needs repo, branches |
| [VNX-GH-219](#vnx-gh-219) | Repository secret used by an untrusted-trigger workflow | high | CWE-200, CWE-668 | needs repo |

## Organisation settings — `vulnetix gha org`

| ID | Rule | Severity | CWE | Context |
|---|---|---|---|---|
| [VNX-GH-301](#vnx-gh-301) | Organisation does not require two-factor authentication | high | CWE-308 | needs org |
| [VNX-GH-302](#vnx-gh-302) | Broad default repository permission for members | medium | CWE-276 | needs org |
| [VNX-GH-303](#vnx-gh-303) | Members can create public repositories | low | CWE-200 | needs org |
| [VNX-GH-304](#vnx-gh-304) | Organisation allows any action | medium | CWE-829 | needs org |
| [VNX-GH-305](#vnx-gh-305) | Organisation workflow token defaults to write | medium | CWE-250, CWE-276 | needs org |
| [VNX-GH-306](#vnx-gh-306) | Organisation secret visible to every repository | medium | CWE-200, CWE-668 | needs org |
| [VNX-GH-307](#vnx-gh-307) | Self-hosted runners available to public repositories | high | CWE-668, CWE-829 | needs runner_groups |
| [VNX-GH-308](#vnx-gh-308) | Organisation lets Actions approve pull requests | medium | CWE-862 | needs org |
| [VNX-GH-309](#vnx-gh-309) | Organisation webhook deliveries can be forged or intercepted | medium | CWE-345, CWE-295 | needs org |

## Rule details

### VNX-GH-001

**Untrusted input expanded into an executed script** — A ${{ }} expression carrying attacker-controlled text is substituted into a shell or script before it runs.

GitHub substitutes ${{ }} expressions into run: scripts (and script inputs such as actions/github-script's script) as text, before the interpreter parses them. Text that an outsider controls — a pull request title, a branch name, a comment, a commit message — becomes code that runs with the job's token and secrets. The engine follows the value through env:, GITHUB_ENV, step outputs, job outputs and local composite actions, and only reports sources the workflow's triggers can actually populate.

**Remediation.** Pass the value through an environment variable and reference it as a shell variable ("$TITLE"), or as process.env in github-script, so it is data rather than code.

### VNX-GH-002

**Untrusted input written to GITHUB_ENV or GITHUB_PATH** — Attacker-controlled text is appended to the job's environment or PATH file.

Lines appended to $GITHUB_ENV become environment variables for every later step, and lines appended to $GITHUB_PATH prepend directories to PATH. A value containing a newline can define LD_PRELOAD, NODE_OPTIONS, BASH_ENV or a new PATH entry, giving code execution in later steps even when those steps are written safely.

**Remediation.** Do not write untrusted values to GITHUB_ENV/GITHUB_PATH. If a later step needs the value, pass it through a step output and env:, or use a random heredoc delimiter and validate the value first.

### VNX-GH-003

**Privileged workflow runs code from an untrusted pull request** — A pull_request_target, workflow_run or comment-triggered job checks out the pull request's code and then executes it.

pull_request_target, workflow_run and issue_comment run in the base repository's context: a write-capable GITHUB_TOKEN and every secret. Checking out the pull request head and then running a script, a build, or a local action executes code the pull request author wrote with those privileges. Build scripts, package manager hooks, test configuration and local actions all count as execution.

**Remediation.** Split the work: run untrusted code under pull_request (no secrets, read-only token) and hand results to a privileged workflow as data via an artifact. If the privileged job must see the code, never execute it — and gate the job on an environment with required reviewers.

### VNX-GH-004

**Checkout credentials persisted into an uploaded workspace** — actions/checkout writes the token into .git/config and the workspace is then uploaded as an artifact.

By default actions/checkout stores the job's GITHUB_TOKEN in .git/config so later git commands authenticate. Uploading the checkout directory as an artifact publishes that token to anyone who can download the run's artifacts — on a public repository, everyone — while the job is still running.

**Remediation.** Set persist-credentials: false on actions/checkout, and upload only the build output directory, never the repository root.

### VNX-GH-005

**Privileged workflow consumes artifacts from an untrusted run** — A workflow_run job downloads artifacts produced by a fork-triggered run and extracts them into the workspace.

Artifacts uploaded by a pull_request run are written by the pull request's code. A workflow_run job that downloads them into the working directory lets that code overwrite scripts, configuration or binaries the privileged job then uses.

**Remediation.** Download into a dedicated directory outside the workspace (e.g. ${{ runner.temp }}/artifacts), treat contents as untrusted data, and validate them before use. Never execute anything from the artifact.

### VNX-GH-006

**Release workflow restores a cache writable by untrusted runs** — A workflow that publishes releases restores dependency caches that other workflows on the default branch can write.

Caches are shared across workflows in the same branch scope. A compromised or injectable workflow on the default branch can save a poisoned cache entry that a release workflow later restores and ships inside a published artifact.

**Remediation.** Disable caching in workflows that publish releases or sign artifacts (remove cache: / actions/cache), or use a cache key namespace no other workflow writes.

### VNX-GH-007

**Workflow token permissions not declared** — Neither the workflow nor the job declares permissions:, so the token gets the repository default.

Without a permissions: block the GITHUB_TOKEN gets the repository or organisation default, which for many repositories is read/write on every scope. Any compromised step — a vulnerable action, an injection — can then push code, publish packages or approve pull requests.

**Remediation.** Add `permissions: {}` (or `contents: read`) at the top of the workflow, and grant individual jobs only the scopes they need.

### VNX-GH-008

**Excessive token permissions** — The token is granted write-all, or write scopes at workflow level that every job inherits.

write-all grants every scope including actions, packages, pages and id-token. Workflow-level write scopes apply to every job, including jobs that run untrusted code or third-party actions.

**Remediation.** Use `permissions: {}` at the workflow level and grant each job only the specific scopes it needs.

### VNX-GH-009

**OIDC token minted outside a protected environment** — A job with id-token: write is not bound to an environment with reviewers or a branch policy.

id-token: write lets the job request an OIDC token that cloud providers exchange for credentials. Cloud trust policies commonly match on repository only; without an environment gate, any branch, and any code that can run in that job, can obtain cloud credentials.

**Remediation.** Bind the job to an environment with required reviewers or a protected-branch policy, and scope the cloud trust policy's subject to that environment (repo:owner/name:environment:prod).

### VNX-GH-010

**All secrets passed to a reusable workflow** — secrets: inherit hands every repository, environment and organisation secret to the called workflow.

The called workflow receives every secret the caller can see, not just the ones it uses. A reusable workflow in another repository, or one pinned to a mutable ref, becomes a way to exfiltrate all of them.

**Remediation.** Pass only the secrets the called workflow declares under on.workflow_call.secrets, by name.

### VNX-GH-011

**Secrets context exposed in bulk** — toJSON(secrets) or a computed secrets[...] index loads every secret into the job.

Secrets are only sent to a runner when referenced. toJSON(secrets) or a dynamic index forces every secret the workflow can see onto the runner, so a single compromised step can read all of them, and log masking is weaker for structured values.

**Remediation.** Reference each secret by name, only in the step that needs it.

### VNX-GH-012

**Hard-coded container registry credentials** — A job container or service declares a literal password instead of a secret reference.

Credentials written into the workflow file are visible to anyone who can read the repository and persist in git history.

**Remediation.** Store the password as an Actions secret and reference it as ${{ secrets.NAME }}. Rotate the exposed credential.

### VNX-GH-013

**Deprecated workflow commands re-enabled** — ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables ::set-env and ::add-path.

With this variable set, any process that prints to stdout — a test, a dependency, a log line containing user text — can set environment variables or PATH for later steps by printing a workflow command.

**Remediation.** Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and write to $GITHUB_ENV / $GITHUB_PATH instead.

### VNX-GH-014

**Authorisation by spoofable actor name** — An if: trusts github.actor == '<bot>[bot]' in a workflow outsiders can trigger.

github.actor is whoever caused the latest event, not who wrote the code. An attacker can open a pull request that a bot later updates (for example by asking Dependabot to rebase), making the bot the actor while the attacker's commits run with the privileges the check was meant to reserve for the bot.

**Remediation.** Check the pull request author (github.event.pull_request.user.login) and that the head repository is the base repository, or use the bot's own metadata action.

### VNX-GH-015

**Condition always evaluates to true** — An if: mixes ${{ }} with surrounding text, or is a block scalar, so it is a non-empty string and always true.

When an if: value contains text outside a single ${{ }} expression (including a trailing newline from a | block), GitHub evaluates the whole thing as a string, and any non-empty string is truthy. The guard — often an authorisation check — never blocks.

**Remediation.** Write the condition as a single expression, either bare (if: a && b) or entirely inside one ${{ }}.

### VNX-GH-016

**Self-hosted runner reachable from pull requests** — A job triggered by pull requests runs on a self-hosted runner.

Self-hosted runners are not ephemeral by default: code from a pull request can persist on the machine, read credentials from earlier jobs, and reach the internal network the runner sits on. On a public repository any GitHub user can trigger this.

**Remediation.** Run pull request workflows on GitHub-hosted runners, or on ephemeral (just-in-time) self-hosted runners in an isolated runner group that public repositories cannot use.

### VNX-GH-017

**Secret printed to the job log** — A run: step prints a secret, relying on log masking to hide it.

Masking only redacts exact matches. Encoded, split or transformed output (base64, JSON, a substring, a multi-line value) is printed in clear to a log readable by everyone with read access.

**Remediation.** Never print secrets. Pass them to tools through environment variables or files with restricted permissions.

### VNX-GH-018

**Comment-triggered workflow without an author check** — An issue_comment workflow runs privileged steps for any commenter.

issue_comment runs with a write token and secrets, and anyone who can comment can trigger it. A ChatOps command (/deploy, /release, /retest) without an author_association or permission check runs for every GitHub user on a public repository.

**Remediation.** Gate the job on github.event.comment.author_association being OWNER, MEMBER or COLLABORATOR, or check the commenter's permission with the API before acting.

### VNX-GH-019

**Obfuscated action reference or expression** — A uses: path or ${{ }} expression is written in a form that hides what it resolves to.

uses: owner/repo/./@ref and github['event']['issue']['title'] resolve to the same thing as their plain forms but evade reviewers, allow-lists and simple scanners. Legitimate workflows rarely need them.

**Remediation.** Write the reference or expression in its plain form.

### VNX-GH-020

**Pull request head ref used as a branch or tag name without quoting** — A shell variable holding the head branch name is passed to git or gh unquoted or without --.

Moving an untrusted value into env: fixes script injection, but `git checkout $BRANCH` still lets a branch named --upload-pack=... or -o... inject options. Branch names can start with a dash.

**Remediation.** Quote the variable and end option parsing: git checkout -- "$BRANCH" (or git switch "refs/heads/$BRANCH").

### VNX-GH-101

**Action or reusable workflow not pinned to a commit SHA** — uses: references a branch or tag, which the action's owner (or anyone who compromises them) can move.

Tags and branches are mutable. When an action repository is compromised, the attacker re-points existing tags at malicious code and every workflow referencing them runs it on its next execution — as happened in widely used actions. A full 40-character SHA is the only immutable reference.

**Remediation.** Pin to the full commit SHA and keep the version in a trailing comment (uses: owner/repo@<sha> # v1.2.3); let Dependabot or Renovate update both.

### VNX-GH-102

**SHA pin does not match its version comment** — uses: owner/repo@<sha> # vX.Y.Z, but vX.Y.Z resolves to a different commit.

Reviewers and update bots read the version comment, not the SHA. A SHA that does not match its comment either predates an update that only changed the comment, or was swapped deliberately to run a different commit under a trusted-looking version.

**Remediation.** Re-pin to the commit the intended version resolves to, and update the comment and SHA together.

### VNX-GH-103

**Pinned commit is not in the action's repository** — The pinned SHA exists only in a fork of the action repository.

GitHub serves commits from any fork through the parent repository's URL. An attacker can push malicious code to a fork and propose a pin to that SHA; it looks like owner/repo@<sha> but the commit was never part of owner/repo.

**Remediation.** Replace the SHA with one that is reachable from a branch or tag of the action repository itself.

### VNX-GH-104

**Action repository archived, missing or hijackable** — The referenced action is archived, deleted, or its owner was renamed or removed.

An archived action gets no security fixes. A deleted repository, or an owner that was renamed or removed, lets anyone register the old name and publish code under it (repo-jacking); unpinned references then run it.

**Remediation.** Replace the action with a maintained alternative, or vendor it into this repository as a local action.

### VNX-GH-105

**Action version has a published vulnerability** — The referenced version of the action is affected by a known advisory.

Actions are dependencies. A vulnerable version — command injection through its inputs, credential leakage, or a compromised release — exposes every workflow that runs it.

**Remediation.** Upgrade to the fixed version named in the advisory and re-pin to its SHA.

### VNX-GH-106

**Container image not pinned to a digest** — docker:// steps, job containers and services reference an image by tag.

Image tags are mutable. The image that runs with the job's token and workspace can change without any change to the workflow.

**Remediation.** Reference images by digest (image@sha256:...), and let an update bot refresh it.

### VNX-GH-107

**Action major version runs on a retired runtime** — The action version uses a Node.js runtime or backend service GitHub has retired.

Retired runtimes receive no security patches and are forced onto newer runtimes by the runner, which can change behaviour; retired artifact and cache backends fail outright.

**Remediation.** Upgrade to the current major version of the action.

### VNX-GH-108

**Action not permitted by the allowed-actions policy** — The workflow references an action that the repository's allowed-actions policy does not list.

The run will fail at start-up, or — if the policy is relaxed to make it pass — the allow-list stops meaning anything. Either way the drift should be resolved deliberately.

**Remediation.** Replace the action with an allowed one, or add it (pinned) to the allow-list after review.

### VNX-GH-109

**Action owner resembles a popular publisher** — The action's owner is one character away from a widely used publisher.

Typosquatted owners (actoins/checkout, aws-action/...) are registered to catch mistyped references and run attacker code with the job's privileges.

**Remediation.** Check the owner's spelling; reference the intended publisher.

### VNX-GH-111

**Remote script piped into an interpreter** — A run: step downloads a script and executes it without verifying it.

curl | sh runs whatever the server returns at that moment, with the job's token and secrets. A compromised host, CDN or DNS response becomes code execution in CI.

**Remediation.** Download to a file, verify a pinned checksum or signature, then execute it — or use a pinned action or package instead.

### VNX-GH-201

**Default branch is not protected** — Neither branch protection nor a ruleset applies to the default branch.

Anyone with write access — including a compromised token, a leaked deploy key, or a workflow with contents: write — can push directly to the default branch, rewrite its history or delete it, and the change ships without review.

**Remediation.** Add a ruleset targeting the default branch that requires pull requests with at least one approval, blocks force pushes and deletions, and requires status checks.

### VNX-GH-202

**Default branch merges without review** — Protection exists but requires no approving review.

Without a required approval a single account — or a single stolen credential — can land any change on the default branch.

**Remediation.** Require at least one approving review (two for repositories that publish releases), and require approval of the most recent push.

### VNX-GH-203

**Approvals survive new commits** — Stale reviews are not dismissed and approval of the last push is not required.

An author can get a harmless change approved, then push different code and merge on the old approval.

**Remediation.** Enable dismiss stale approvals and require approval of the most recent reviewable push.

### VNX-GH-204

**Workflow changes bypass code owners** — CODEOWNERS does not cover .github/workflows, or code owner review is not required.

Workflows hold the keys: secrets, deployment credentials and release signing. If any approver can sign off a workflow change, a reviewer unfamiliar with CI security can approve a change that exfiltrates secrets.

**Remediation.** Add `/.github/ @your-org/ci-owners` to CODEOWNERS and require code owner review on the default branch.

### VNX-GH-205

**Force pushes or deletion allowed on the default branch** — Protection permits force pushes or deleting the branch.

A force push rewrites history that downstream builds, tags and audits rely on, and can remove a reviewed change after the fact.

**Remediation.** Block force pushes and deletions on the default branch.

### VNX-GH-206

**Branch protection can be bypassed** — Administrators are exempt, or a broad role or app is a ruleset bypass actor.

An exemption is a standing path around review. Admin accounts and app installations are the highest-value credentials to steal precisely because they skip the controls.

**Remediation.** Enforce protection for administrators and limit ruleset bypass to a named break-glass team with pull-request-only bypass.

### VNX-GH-207

**No required status checks** — Pull requests can merge with failing or missing CI.

Security checks (tests, scanners, signature verification) only protect the branch if a failing result blocks the merge.

**Remediation.** Require the security-relevant checks to pass before merging.

### VNX-GH-208

**Workflow token defaults to write** — Workflows without a permissions: block get a read/write token.

Every workflow that omits permissions: — including ones added later by contributors — runs with write access to contents, packages, issues and pull requests.

**Remediation.** Set Settings → Actions → General → Workflow permissions to "Read repository contents and packages permissions".

### VNX-GH-209

**GitHub Actions can approve pull requests** — Workflows may create and approve pull requests.

A workflow token that can approve pull requests satisfies a one-approval rule on its own: one compromised workflow opens and approves its own change.

**Remediation.** Disable "Allow GitHub Actions to create and approve pull requests".

### VNX-GH-210

**Fork pull request workflows run without approval** — Outside contributors' pull requests run workflows without a maintainer approving them, or private-repo forks get secrets or write tokens.

Approval is the human check before an outsider's code runs on your runners. Only requiring it for accounts new to GitHub lets any established account — or a bought one — run code immediately. On private repositories, sending secrets or write tokens to fork workflows hands them to every fork.

**Remediation.** Require approval for all outside collaborators; on private repositories, do not send write tokens or secrets to fork pull request workflows.

### VNX-GH-211

**Any action may run** — The allowed-actions policy permits every action and reusable workflow.

With no allow-list a contributor can introduce any third-party action in a pull request, and it runs on merge with the workflow's token and secrets.

**Remediation.** Allow GitHub-owned and verified-creator actions plus an explicit list, and require SHA pinning.

### VNX-GH-212

**Secret scanning or push protection disabled** — Committed credentials are neither blocked at push time nor alerted on.

Push protection stops a credential before it reaches history; secret scanning finds the ones that got through. Without either, a leaked key is found first by whoever is looking.

**Remediation.** Enable secret scanning and push protection.

### VNX-GH-213

**Dependabot security updates disabled** — Vulnerable dependencies, including pinned actions, are not raised as update pull requests.

SHA-pinned actions only stay safe if something updates them. Security updates open the fix as a pull request as soon as an advisory is published.

**Remediation.** Enable Dependabot security updates, and add a github-actions ecosystem entry to dependabot.yml.

### VNX-GH-214

**Environment secrets deployable without approval** — An environment holds secrets but has no required reviewers and no branch policy.

Environment secrets exist so that only gated jobs see them. An ungated environment gives its secrets to any job on any branch that names it — including a branch pushed by any writer.

**Remediation.** Add required reviewers (with prevent self-review) or restrict the environment to protected branches.

### VNX-GH-215

**Deploy key with write access** — A deploy key can push to the repository.

Deploy keys are not tied to a user, do not expire, and are typically stored on build or deployment hosts. A write key there can push to unprotected branches and tags.

**Remediation.** Make the key read-only, or replace it with a GitHub App installation token scoped to the repository.

### VNX-GH-216

**Webhook deliveries can be forged or intercepted** — A repository webhook has no secret, or disables TLS verification.

Webhooks often drive deployments. Without a signing secret anyone can forge an event; without TLS verification the payload (and anything it triggers) can be intercepted or altered.

**Remediation.** Set a webhook secret and verify X-Hub-Signature-256 on receipt; enable SSL verification.

### VNX-GH-217

**Outside collaborator with admin access** — Someone outside the organisation can change protection, secrets and settings.

Admin access includes disabling branch protection, reading environment configuration and adding deploy keys. Outside collaborators are not covered by the organisation's 2FA, SSO and offboarding.

**Remediation.** Reduce outside collaborators to write or lower, or bring them into the organisation.

### VNX-GH-218

**Signed commits not required** — The default branch accepts unsigned commits.

Commit author fields are free text. Without signature verification a commit can claim any author, which undermines audit trails and author-based automation.

**Remediation.** Require signed commits on the default branch.

### VNX-GH-219

**Repository secret used by an untrusted-trigger workflow** — A repository-level secret (not an environment secret) is read by a workflow outsiders can trigger.

Repository secrets are available to every job. When a pull_request_target, issue_comment or workflow_run workflow reads one, any flaw in that workflow exposes it; an environment secret would add a gate.

**Remediation.** Move the secret to an environment with required reviewers, and reference it only from the job bound to that environment.

### VNX-GH-301

**Organisation does not require two-factor authentication** — Members and outside collaborators can sign in with a password alone.

Every member account is a path to every repository it can write to. Phished or reused passwords are the most common way into an organisation.

**Remediation.** Require two-factor authentication for the organisation.

### VNX-GH-302

**Broad default repository permission for members** — Every member gets write or admin on every repository.

With a write default, one compromised member account can push to, and run workflows in, every repository in the organisation.

**Remediation.** Set the base permission to read or none and grant write through teams.

### VNX-GH-303

**Members can create public repositories** — Any member can publish a repository under the organisation's name.

Public repositories can be created by mistake with internal code, or used to host look-alike actions that appear to be official.

**Remediation.** Restrict public repository creation to owners.

### VNX-GH-304

**Organisation allows any action** — The organisation policy permits every action and reusable workflow in every repository.

An organisation-wide allow-list is the one control that stops a new, unreviewed third-party action from running anywhere.

**Remediation.** Allow GitHub-owned, verified-creator and explicitly listed actions only.

### VNX-GH-305

**Organisation workflow token defaults to write** — New repositories inherit a read/write workflow token.

The organisation default sets the ceiling for every repository that does not override it, including every repository created from now on.

**Remediation.** Set the organisation's default workflow permissions to read.

### VNX-GH-306

**Organisation secret visible to every repository** — An organisation secret has visibility all, so any repository — including public ones — can read it.

A secret shared with all repositories is only as safe as the weakest workflow in the organisation. With visibility all, public repositories' workflows can read it too.

**Remediation.** Set the secret's visibility to selected repositories, or private repositories at most.

### VNX-GH-307

**Self-hosted runners available to public repositories** — A runner group with self-hosted runners allows public repositories.

Any GitHub user can trigger pull_request workflows in a public repository. If those jobs can land on your self-hosted runners, outsiders run code inside your network.

**Remediation.** Disable "Allow public repositories" on runner groups that contain self-hosted runners, or make those runners ephemeral and network-isolated.

### VNX-GH-308

**Organisation lets Actions approve pull requests** — Workflows across the organisation may create and approve pull requests.

Repositories inherit this permission; a workflow token can then satisfy one-approval rules by approving its own pull request.

**Remediation.** Disable "Allow GitHub Actions to create and approve pull requests" at the organisation level.

### VNX-GH-309

**Organisation webhook deliveries can be forged or intercepted** — An organisation webhook has no secret, or disables TLS verification.

Organisation webhooks receive events from every repository. An unsigned or unverified hook lets an attacker forge or read them.

**Remediation.** Set a webhook secret and enable SSL verification.
