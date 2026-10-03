#!/usr/bin/env bash
# Deploys the Worker to production (https://x402check.xyz) from a commit that CI tested.
#
# It refuses to deploy unless:
#   1. the working tree is clean (no staged, unstaged or untracked files);
#   2. HEAD is the tip of main on GitHub (asked with git ls-remote, so a stale local
#      origin/main cannot pass);
#   3. the `ci` workflow's push run for that commit on main completed successfully;
#   4. the OFAC snapshot embedded in the Worker is not older than the published feeds release
#      (a new isolate screens against it until its first refresh lands): otherwise run
#      `npx tsx scripts/sync-embedded-feeds.ts`, commit and push first. SKIP_FEEDS_CHECK=1
#      skips this, for an emergency only.
# Then it installs the locked dependencies (npm ci without install scripts, as the feeds workflow does) and runs `wrangler deploy`
# from deploy/ with GIT_COMMIT=<short SHA> (for /healthz), tagging the Cloudflare Worker
# version with the same commit.
#
# Needs git, gh (logged in), npm, and wrangler logged in to the Cloudflare account. It runs
# the wrangler pinned in package.json when there is one, otherwise the one installed on this
# machine, and never downloads one (npx --no).
# To roll back, use `npx wrangler rollback` (Cloudflare keeps earlier versions).
set -euo pipefail

die() {
  printf 'deploy: %s\n' "$*" >&2
  exit 1
}

cd "$(dirname "$0")/.."
command -v gh > /dev/null 2>&1 || die "gh (GitHub CLI) is required to check CI"

# 1. Clean tree.
dirty=$(git status --porcelain --untracked-files=normal)
if [ -n "$dirty" ]; then
  printf '%s\n' "$dirty" >&2
  die "the working tree is not clean: commit, stash or remove the changes above first"
fi

# 2. HEAD is main on GitHub.
head=$(git rev-parse --verify HEAD)
remote_main=$(git ls-remote --exit-code origin refs/heads/main | cut -f1) \
  || die "could not read main from origin"
[ "$head" = "$remote_main" ] \
  || die "HEAD ($head) is not main on GitHub ($remote_main): deploy only what is pushed to main"

# 3. CI passed on that commit.
repo=$(git remote get-url origin | sed -E 's#^(https://github\.com/|git@github\.com:|ssh://git@github\.com/)##; s#\.git$##')
ci=$(gh run list --repo "$repo" --workflow ci.yml --branch main --event push --commit "$head" \
  --limit 1 --json status,conclusion,url \
  --jq '.[0] | select(. != null) | "\(.status) \(if (.conclusion // "") == "" then "none" else .conclusion end) \(.url)"') \
  || die "could not list CI runs with gh (is it logged in?)"
[ -n "$ci" ] || die "no ci run on main for $head yet"
read -r status conclusion url <<< "$ci"
[ "$status" = completed ] || die "CI on $head is still $status: $url (wait with: gh run watch ${url##*/})"
[ "$conclusion" = success ] || die "CI did not pass on $head ($conclusion): $url"
echo "deploy: $head is main on GitHub and passed CI ($url)"

# The dependency tree exactly as locked, as CI built it.
npm ci --ignore-scripts --no-audit --no-fund

# 4. The embedded OFAC snapshot is the published release (or newer).
if [ "${SKIP_FEEDS_CHECK:-}" != "1" ]; then
  npx --no -- tsx scripts/sync-embedded-feeds.ts --check \
    || die "the embedded OFAC snapshot is not current: run npx tsx scripts/sync-embedded-feeds.ts, commit, push and wait for CI (SKIP_FEEDS_CHECK=1 skips this, in an emergency only)"
fi

short=$(git rev-parse --short=12 HEAD)
cd deploy
wrangler=(npx --no -- wrangler)
version=$("${wrangler[@]}" --version | tail -n 1) \
  || die "wrangler is not installed (pin it in package.json, or install it); nothing was deployed"
echo "deploy: wrangler $version, GIT_COMMIT=$short"
"${wrangler[@]}" deploy --var "GIT_COMMIT:$short" --tag "$short" --message "git $head"
echo "deploy: done. Check https://x402check.xyz/healthz and /status (AGENTS.md §3.2)."
