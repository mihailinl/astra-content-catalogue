#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Minice — https://minice.ai
#
# Place each kind's CURRENT signing key as its environment's secret.
# The operator runs this; no workflow and no agent does. See owner/secrets.mjs
# for what it checks before it uploads anything.
#
#   owner/secrets.sh <keys-dir> [--rotate <kind>] [--trust <file>] [--repo <owner/name>]
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v node >/dev/null || { echo "node (>= 22) is needed" >&2; exit 1; }
command -v gh >/dev/null || { echo "gh is needed" >&2; exit 1; }
exec node "$here/secrets.mjs" "$@"
