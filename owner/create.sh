#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Minice — https://minice.ai
#
# Set up the repository's environments and branch rules, and print the two
# ids the plugins service pins. The operator runs this once, with a `gh` that
# is signed in as an administrator of the repository; running it again changes
# nothing. It uploads no key (owner/secrets.sh does) and creates no repository.
#
#   owner/create.sh [<owner/name>]        default mihailinl/astra-content-catalogue
#
# What it sets:
#
#   environments   content-service and publish-<kind> for the five kinds,
#                  each deployable from `main` only. A job on any other
#                  branch cannot enter one, so it cannot mint the service's
#                  token (content-service) or read a key (publish-<kind>).
#   main           ruleset `main: no deletion, no forced update`, for everybody,
#                  with no bypass.
#                  ruleset `main: updated by administrators only`: updating
#                  the branch is restricted, and the repository's admin role
#                  is the one bypass actor. This is what keeps the code the
#                  signing legs run out of reach of everything but an
#                  administrator: a signing leg's own token can write
#                  contents (it must, to push `data`), GitHub cannot limit a
#                  token to one branch, and without this rule that token, or
#                  any collaborator with write access, could change the code
#                  on `main` that the next run executes beside the keys.
#                  owner/secrets.sh uploads no key until this ruleset exists
#                  and is active.
#   data           ruleset `data: forward only`: no deletion and no forced
#                  update, for everybody, with no bypass.
#                  ruleset `data: written by the workflow only`: creating and
#                  updating the branch is restricted, and GitHub Actions is
#                  the one bypass actor, so only a workflow run's token
#                  pushes it. The two are separate rulesets because a bypass
#                  actor bypasses every rule of the ruleset it is listed on,
#                  and the workflow must not be able to force or delete.
set -euo pipefail

REPO="${1:-mihailinl/astra-content-catalogue}"
KINDS=(commands characters models animsets packs)
# The GitHub Actions app, the actor behind a workflow run's token.
ACTIONS_APP_ID=15368
# The repository role `admin`, as rulesets number it.
ADMIN_ROLE_ID=5

api() { gh api -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" "$@"; }

environment() {
  local name="$1"
  api --method PUT "repos/$REPO/environments/$name" --input - >/dev/null <<'JSON'
{"deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
JSON
  local policies
  policies="$(api "repos/$REPO/environments/$name/deployment-branch-policies" --jq '.branch_policies[] | select(.type == "branch") | .name')"
  if ! grep -qx main <<<"$policies"; then
    api --method POST "repos/$REPO/environments/$name/deployment-branch-policies" --input - >/dev/null <<'JSON'
{"name": "main", "type": "branch"}
JSON
  fi
  local others
  # anything but the branch main, a TAG policy named main included
  others="$(api "repos/$REPO/environments/$name/deployment-branch-policies" --jq '[.branch_policies[] | select(.name != "main" or .type != "branch") | "\(.type) \(.name)"] | join(", ")')"
  if [ -n "$others" ]; then
    echo "environment $name also allows: $others — remove them by hand; this script removes nothing" >&2
    exit 1
  fi
  echo "environment $name: main only"
}

# ruleset <name> <json body>: created, or replaced in place when one of that name exists
ruleset() {
  local name="$1" body="$2" ids id
  ids="$(api "repos/$REPO/rulesets" --paginate --jq ".[] | select(.name == \"$name\") | .id")"
  id="$(head -n 1 <<<"$ids")"
  if [ -n "$id" ]; then
    printf '%s' "$body" | api --method PUT "repos/$REPO/rulesets/$id" --input - >/dev/null
  else
    printf '%s' "$body" | api --method POST "repos/$REPO/rulesets" --input - >/dev/null
  fi
  echo "ruleset \"$name\": set"
}

environment content-service
for kind in "${KINDS[@]}"; do environment "publish-$kind"; done

ruleset "main: no deletion, no forced update" '{
  "name": "main: no deletion, no forced update", "target": "branch", "enforcement": "active",
  "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
  "bypass_actors": [],
  "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}]
}'
ruleset "main: updated by administrators only" '{
  "name": "main: updated by administrators only", "target": "branch", "enforcement": "active",
  "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
  "bypass_actors": [{"actor_id": '"$ADMIN_ROLE_ID"', "actor_type": "RepositoryRole", "bypass_mode": "always"}],
  "rules": [{"type": "update"}]
}'
ruleset "data: forward only" '{
  "name": "data: forward only", "target": "branch", "enforcement": "active",
  "conditions": {"ref_name": {"include": ["refs/heads/data"], "exclude": []}},
  "bypass_actors": [],
  "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}]
}'
ruleset "data: written by the workflow only" '{
  "name": "data: written by the workflow only", "target": "branch", "enforcement": "active",
  "conditions": {"ref_name": {"include": ["refs/heads/data"], "exclude": []}},
  "bypass_actors": [{"actor_id": '"$ACTIONS_APP_ID"', "actor_type": "Integration", "bypass_mode": "always"}],
  "rules": [{"type": "creation"}, {"type": "update"}]
}'

echo
echo "The plugins service pins these two ids (contract BOT-110):"
api "repos/$REPO" --jq '"repository_id        \(.id)\nrepository_owner_id  \(.owner.id)"'
