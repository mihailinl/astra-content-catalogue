# astra-content-catalogue

The signer of the Astra Workshop content documents.

Astra's Workshop lists five kinds of content: `commands`, `characters`,
`models`, `animsets` and `packs`. For each kind a client reads two signed
documents: an **index** (what is listed) and a **withdrawn** document (what
has been withdrawn, including a confirmed removal under the content rules).
This repository signs those ten documents and publishes them on its `data`
branch. It holds the signing keys and no content; the plugins service holds
the content and no key.

The document formats, the signature and every rule a document must satisfy
are specified in AstraPlugins, [`spec/content/`](https://github.com/mihailinl/AstraPlugins/tree/master/spec/content).
The wire between the service and this repository is the server registry
contract, §4.7 (BOT-110, BOT-111, TRUST-50, SERVE-116).

## The flow

`sign.yml` runs every ten minutes and on a manual dispatch.

1. **`work`** asks the plugins service for each kind:
   `GET https://api.minice.ai/plugins/v1/bot/content/<kind>/accepted`. The
   answer, `astra.content.export/1`, carries the kind's complete unsigned
   index entries, its withdrawn rows and lifts, `generated_at` and
   `state_sha256`. The job proves who it is with a GitHub OIDC token for the
   audience `https://api.minice.ai/plugins/v1/content`, one token per call.
   It runs in the environment `content-service` and holds **no secret**. The
   service address is a constant in the code: no variable can send the token
   elsewhere.
2. **`sign`** runs one leg per kind, one after another, each in that kind's
   own environment `publish-<kind>`. A leg holds that kind's key and **no
   OIDC token**, and is five steps:

   | step | holds | does |
   |---|---|---|
   | open | the job's token | checks out `data` |
   | prepare | nothing | reads the answer and the kind's last signed pair, checks, writes the two unsigned bodies |
   | sign | **the key** | one Node file that starts no process and opens no connection; signs the two prepared bodies |
   | verify | nothing | proves what was signed, then puts the three files in place |
   | publish | the job's token | one commit on `data`, pushed forward |

   The code that parses bytes the service chose, and the specification's
   checker, run in *prepare* and *verify*, never in the step that has the
   key.

   *prepare* refuses the kind unless all of this holds:
   - the answer is strictly readable JSON with exactly the members of the
     export schema, and `generated_at` is within the last 30 minutes (so a
     re-run of an old run, or an old answer offered again, is not signed
     under a new serial);
   - the kind's last signed pair on `data` verifies under the kind's keys in
     `trust.json`. The rows to keep, the serial and the key that signed last
     are taken from those verified documents, never from an unverified file;
     `state/<kind>.json` must agree with them. A kind with no pair is signed
     for the first time only if no commit on `data` ever touched its paths;
     no symbolic link is followed;
   - this machine's clock is later than the serial signed last. `issued_at`
     = `serial` = that clock, `expires_at` seven days on;
   - every withdrawn row of the last document that the answer omits without
     a lift is kept (see below);
   - both documents pass the specification's own checker (schema, semantic
     rules, pairing rules) and neither exceeds 1,048,576 bytes.

   *sign* signs both with the kind's key (see Keys), under the domains
   `astra.<kind>.index/1` and `astra.<kind>.withdrawn/1`, and only bodies
   that are canonical JSON for that kind and that second.

   *verify* checks that each signed document is exactly the body that was
   prepared, carries one signature, and verifies under the kind's key from
   `trust.json`, by this repository's code and again by the specification's
   verifier. Only then are `registry/v1/<kind>/index.json`,
   `registry/v1/<kind>/withdrawn.json` and `state/<kind>.json` written, and
   *publish* commits the three in one commit. `data` only moves forward.

   A kind whose answer is the one signed less than six hours ago, under the
   key the leg holds, is left as it is.
3. The plugins service mirrors `data`, verifies each pair again exactly as a
   client does, and serves it.

A kind that cannot be signed fails its own leg and keeps its last signed
pair; the other kinds are signed as usual. A failed step prints a code such
as `E_EXPORT_STALE` and, at most, a location spelt in the schema's own
words. It never prints a value or a member name from the answer.

**When the service door is not open** for a kind (HTTP 404, or `unavailable`)
that kind is left alone and the run stays green, provided the kind has never
been published or was signed within the last twelve hours. A published kind
whose door has stayed shut for longer fails the run, because its withdrawn
document is going stale. Each kind is judged by itself. Any other refusal
fails the run.

### A withdrawn row leaves only through a lift

The service states a kind's withdrawn rows afresh in every answer. If a row
that was published is missing from a later answer, and the answer carries no
lift equal to the row on `id`, `versions` and `at`, the signer keeps the row
in the new document, publishes it, and then **fails the run**. The row stays
until the service lifts it or states it again, and the run keeps failing
until then, so that the difference is looked at by a person.

### What is on `data`

| path | what |
|---|---|
| `registry/v1/<kind>/index.json` | the signed index, as RFC 8785 canonical JSON |
| `registry/v1/<kind>/withdrawn.json` | the signed withdrawn document, the same |
| `state/<kind>.json` | `state_sha256` of the answer signed last, its `issued_at`, the `key_id`, and how many rows were kept (`astra.content.signer-state/1`) |

## Keys

Each kind has two keys in the plugin registry's root-signed
[`trust.json`](https://github.com/mihailinl/astra-registry/blob/main/registry/v1/trust.json)
(`kind_keys`): `current` and `next`. A kind key verifies that kind's two
documents and nothing else.

- A kind's environment `publish-<kind>` holds one secret,
  `ASTRA_<KIND>_SIGNING_KEY`: the private half of one of the kind's two keys.
  Normally that is the **current** key. It is read by one step of that
  kind's leg; that step reaches no network.
- The **next** private key stays offline with the operator until the kind is
  rotated (below). The two keys are never in GitHub at the same time.
- The signer signs with the key in the environment only if its public half
  is the kind's current or next key in `trust.json` and that key's
  `not_before` has passed. Any other key, another kind's included, signs
  nothing.
- `trust.json` is read from astra-registry at every run and is believed only
  when it verifies under the root keys compiled into this repository
  (`vendor/astra-registry/bot/lib/roots.mjs`).

## What a compromised service can and cannot do

The service chooses the bytes of every answer. A service that no longer
behaves **can**:

- list an item that should not be listed, or leave a listed item out;
- withhold a new withdrawn row;
- publish a lift for a row.

It already holds the items and the decisions about them, so none of this is a
power it gains through this repository.

It **cannot**:

- obtain a key, or have anything signed for another kind, for the plugin
  catalogue or for `trust.json`: its bytes never reach the step that holds a
  key, and each key verifies one kind under its own domain;
- have a document signed that breaks the specification's rules: the checker
  runs before the key is used, and the service and the client check again;
- roll a document back or replay an old one: an answer older than 30 minutes
  is not signed, the serial is the signer's clock, and the service and every
  client keep a floor per document;
- make a client fetch from an address it chose: an entry carries no address,
  only digests, and a client hashes what it downloads;
- remove a published withdrawn row without saying so: the row is kept and the
  run fails;
- put anything beside the documents into this repository: a member outside
  the export schema is refused, and only `registry/` and `state/` are
  committed.

A stolen key of one kind can sign that kind's two documents and nothing
else, until the kind is rotated.

## Rotating a key

Rotation is an operator act. It needs no change here and leaves no time in
which a kind is unsigned.

1. The operator runs `owner/secrets.sh <keys-dir> --rotate <kind>`. It
   derives the public half of the kind's **next** private key locally,
   refuses unless it equals the kind's next row in `trust.json` and that row
   is valid now, replaces the environment's secret with it, and prints the
   kind, the key id and `ROTATING`.
2. The next run signs both of the kind's documents with that key, at once,
   whether or not the service's answer changed. Clients and the service
   already accept either key of the kind, so nothing else has to happen for
   the documents to verify. The run's log says that it signed with the next
   key; that is not a failure.
3. The trust change follows whenever the root ceremony is held: `trust.json`
   is re-signed so that this key is the kind's `current` row and a new
   `next` row is added. The signer goes on signing with the same secret.

The switch is one-way. A client that has verified a document signed with a
kind's next key refuses a later document of that kind signed with the old
key alone, so the signer refuses to sign a kind with its current key once it
has signed that kind with the next one.

**If a current key is compromised: rotate first, then hold the ceremony.**
Step 1 takes minutes and needs no ceremony; from the first document signed
with the next key, clients that have seen it no longer accept the
compromised key for that kind's documents. The ceremony then removes the
compromised key from `trust.json` for everyone.

A plain `owner/secrets.sh <keys-dir>` uploads current keys only and refuses a
next key. Between steps 1 and 3 it also refuses the rotated kind, because the
kind's documents on `data` are signed with the next key and the current key
would move it back. GitHub does not let a secret be read back, so the script reports
what it uploaded and never what an environment holds; `--no-upload` checks
the key files against `trust.json` and uploads nothing.

### When both keys of a kind are replaced

The signer builds on the kind's last signed pair only after verifying it
under the kind's keys in `trust.json`. A ceremony that removes **both** keys
a pair could have been signed with (it should not be needed: rotate first,
and the key that signed last is still there) leaves a pair nothing can
verify, and the kind's legs fail with `E_PREVIOUS_UNVERIFIED`. That is
deliberate: the alternative is to carry no rows forward. An administrator
resolves it by hand, by deciding which rows stand.

## What protects the keys, and what GitHub cannot enforce

| what must hold | what enforces it |
|---|---|
| a kind's key is read only by that kind's leg | the secret belongs to the environment `publish-<kind>`; an environment deploys from `main` only |
| the code a leg runs is the reviewed code on `main` | the ruleset `main: updated by administrators only` |
| `data` is written only by the workflow, forward only | two rulesets on `data` |
| the service is asked only by this workflow on `main` | the service pins the token's repository id, workflow, ref and environment |

Two things GitHub does not offer, and what stands in for them:

- **A token cannot be limited to one branch.** A signing leg's token has
  `contents: write`, which it needs to push `data`; the same token could
  push `main`. Nothing in the workflow file can prevent that. The ruleset on
  `main` does: only the repository's admin role may update `main`, and a
  workflow token is not an administrator. `owner/secrets.sh` refuses to
  upload any key until that ruleset exists and is active, and until the
  kind's environment deploys from `main` and from nowhere else.
- **A secret cannot be read back.** Nobody can ask GitHub which key an
  environment holds. So the signer derives the public half of whatever key
  it is given and refuses a key that is not one of the kind's two; and
  `owner/secrets.sh` reads which key signed the kind's documents on `data`
  and refuses to put a current key over a rotation in progress.

Steps of one job share a runner. Keeping the checker out of the step that
holds the key means no process started by that step, and no process reading
the service's bytes, ever has the key in its environment; it does not make
the earlier steps of the same job harmless if they were taken over. The
answer's strict schema and the checker's isolated start are what stand
before that.

## Setting the repository up

Both scripts are run by the operator, with `gh` signed in as an administrator
of the repository. Neither is run by a workflow.

```sh
owner/create.sh                 # environments (main only), rulesets for main and data; prints the repository id and owner id
owner/secrets.sh <keys-dir>     # each kind's current key into its environment (--rotate <kind>: that kind's next key)
```

Run `create.sh` first: `secrets.sh` checks what it set before it uploads
anything, and uploads only to the repository whose id is compiled into
`lib/kinds.mjs`. The repository id and owner id that `create.sh` prints are
the ones the service pins.

## Working on it

```sh
npm test                 # Node >= 22 and python3 >= 3.11; no network, no dependencies
node bin/vendor.mjs check --astraplugins <checkout> --astra-registry <checkout>
node bin/vendor.mjs update --astraplugins <checkout> --astra-registry <checkout>
```

The checker, the schemas and the goldens under `vendor/astraplugins/`, and
the signing code under `vendor/astra-registry/`, are copies. `vendor/pins.json`
records the commit and the SHA-256 of each; CI compares every file with that
commit in a checkout of the source. They are never edited here.

| | |
|---|---|
| `bin/fetch.mjs` | `work`: ask the service, hand the answers on |
| `bin/data.mjs` | open `data`; move it forward |
| `bin/prepare.mjs`, `bin/sign.mjs`, `bin/verify.mjs` | the three middle steps of a leg; `sign.mjs` is the one with the key |
| `lib/pipeline.mjs` | prepare and verify: the order of checks |
| `lib/keystep.mjs` | what the step with the key does, and all it can import |
| `lib/state.mjs` | the last signed pair on `data`, proven before use |
| `lib/carry.mjs` | which earlier rows are kept, and how a lift names a row |
| `lib/export.mjs` | `astra.content.export/1`, exactly, and fresh |
| `lib/signer.mjs`, `lib/trust.mjs` | which key may sign, and the root-signed `trust.json` |
| `lib/check.py`, `lib/checker.mjs` | the bridge to the specification's checker |
| `owner/` | the operator's two scripts |

## Licence

GPL-3.0-or-later. Copyright Minice. The files under `vendor/` keep their
sources' licence, which is the same.
