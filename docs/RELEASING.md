# Releasing untrace-sdk

All 4 packages (`@untracenetwork/sdk`, `next`, `react`, `vue`) share one version and are released together. **Pushing a `v*` tag never publishes
anything to npm.** Publishing is a separate, manual step that JC approves.

## One-time setup (JC only, repo admin)

These are GitHub settings. Agents must not change them.

1. **Create the `npm-publish` environment** (Settings -> Environments -> New environment):
   - Required reviewers: **JC** (only JC). Tick "Prevent self-review" if more people get access later.
   - Deployment branches and tags: "Selected branches and tags", add the tag pattern `v*`.
   - Environment secret **`NPM_TOKEN`**: an npm automation (or granular publish) token for the scope
     the packages are published under. Do **not** add `NPM_TOKEN` as a repo or org secret: only the
     environment holds it, so only an approved run of `publish.yml` can read it.
2. **Protect `main`** (Settings -> Branches, or a ruleset): pull request required, the `ci` check
   required, no force push, no deletion.
3. **Add a tag ruleset for `v*`**: only admins may create, update or delete `v*` tags.
4. **npm org `@untracenetwork`** exists, and the `NPM_TOKEN` user can publish to it.
5. **The repository is public before the first publish.** npm rejects `--provenance` from a private
   repository, so `publish.yml` stops with an error while the repo is private. `release.yml` (verify only)
   runs either way.

Only `NPM_TOKEN` is used, so the workflows work unchanged in a fresh copy of this repo.

## Workflows

| Workflow | Trigger | What it does | Secrets / OIDC |
|---|---|---|---|
| `ci.yml` (**CI**) | PRs, pushes to `main` | build, typecheck, test, pack:check | none |
| `release.yml` (**Release (verify)**) | push of a `v*` tag | checks the tag equals every package version, then build, typecheck, test, pack:check and `npm publish --dry-run` for all 4 packages. **Uploads nothing.** | none |
| `publish.yml` (**Publish to npm**) | `workflow_dispatch` only | `verify` job: must be run from a `v*` tag, input `confirm` must equal that tag's version and every package version, then full build and tests. `publish` job: waits in the `npm-publish` environment for JC's approval, then publishes core first and dependents after, with `--provenance` | `NPM_TOKEN` (environment secret) and `id-token: write`, on the `publish` job only |

`test/release-workflows.test.ts` pins these rules, so a change that lets a tag push publish fails CI.

## Cutting a release

1. Bump the version in the root and all 4 `packages/*/package.json`, date the CHANGELOG entry, merge
   the release PR into `main` (CI green).
2. Tag the merge commit and push the tag:
   ```bash
   git tag -s vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
   ```
   The **Release (verify)** run must be green. Nothing has been published at this point.
3. Only with JC's explicit yes: Actions -> **Publish to npm** -> Run workflow -> "Use workflow from":
   **Tags: vX.Y.Z**, `confirm` = `X.Y.Z`. The `publish` job then waits for JC to approve it in the
   `npm-publish` environment.
4. Check `npm view <scope>/sdk@X.Y.Z` and the provenance badge on npmjs.com.

Re-running the publish workflow is safe: versions already on npm are skipped.

**Publish the SDK before the CLI.** untrace-cli depends on `@untracenetwork/sdk` `^2.0.0` from npm; its
`npm ci` and its own publish workflow fail until `@untracenetwork/sdk@2.0.0` is on npm.

## The npm scope (issue #4)

Our packages are published under **`@untracenetwork`**, the same name as the GitHub org (JC, 2026-10-08).
The `@untrace` scope on npm belongs to an unrelated third party (`untrace-dev`): never publish to it and
never tell anyone to `npm i @untrace/...`. The one-time rename was done in the release PR (#3).
