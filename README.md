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
   `GET <service>/bot/content/<kind>/accepted`. The answer,
   `astra.content.export/1`, carries the kind's complete unsigned index
   entries, its withdrawn rows and lifts, and `state_sha256`. The job proves
   who it is with a GitHub OIDC token for the audience
   `https://api.minice.ai/plugins/v1/content`, one token per call. It runs in
   the environment `content-service` and holds **no secret**.
2. **`sign`** runs one leg per kind, one after another, each in that kind's
   own environment `publish-<kind>`. A leg holds that kind's key and **no
   OIDC token**. It:
   - leaves the kind alone when the answer is the one it signed less than six
     hours ago;
   - reads the answer strictly and refuses any member the export schema does
     not name;
   - keeps every withdrawn row of the document it signed last that the answer
     omits without a lift (see below);
   - sets `issued_at` = `serial` = its own clock, which must be later than
     every serial it signed before, and `expires_at` seven days on;
   - checks both documents with the specification's own checker (schema,
     semantic rules, pairing rules) and refuses a document over 1,048,576
     bytes, **before** the key is used;
   - signs both with the kind's key (see Keys), under the domains
     `astra.<kind>.index/1` and `astra.<kind>.withdrawn/1`;
   - verifies what it signed with the public key from `trust.json`;
   - commits `registry/v1/<kind>/index.json`, `registry/v1/<kind>/withdrawn.json`
     and `state/<kind>.json` to `data` in one commit, and pushes it. `data`
     only moves forward.
3. The plugins service mirrors `data`, verifies each pair again exactly as a
   client does, and serves it.

A kind that cannot be signed fails its own leg and keeps its last signed
pair; the other kinds are signed as usual.

**When the service door is not open** (it answers HTTP 404, or `unavailable`)
the `work` job ends green with "service door not open", and no signing leg
starts. Every kind keeps its last signed documents and the next run asks
again. Any other refusal fails the run.

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
  catalogue or for `trust.json`: it never reaches a job that holds a key, and
  each key verifies one kind under its own domain;
- have a document signed that breaks the specification's rules: the checker
  runs before the key is used, and the service and the client check again;
- roll a document back or replay an old one: the serial is the signer's
  clock, and the service and every client keep a floor per document;
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
next key. GitHub does not let a secret be read back, so the script reports
what it uploaded and never what an environment holds; `--no-upload` checks
the key files against `trust.json` and uploads nothing.

## Setting the repository up

Both scripts are run by the operator, with `gh` signed in as an administrator
of the repository. Neither is run by a workflow.

```sh
owner/create.sh                 # environments (main only), rulesets for main and data; prints the repository id and owner id
owner/secrets.sh <keys-dir>     # each kind's current key into its environment (--rotate <kind>: that kind's next key)
```

The repository id and owner id that `create.sh` prints are the ones the
service pins. An optional repository variable `CONTENT_SERVICE_URL` points
`work` at another service base (https only); the audience does not change.

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
| `bin/sign.mjs` | sign one kind (the step with the key) |
| `lib/pipeline.mjs` | the order of checks around one signing |
| `lib/carry.mjs` | which earlier rows are kept, and how a lift names a row |
| `lib/export.mjs` | `astra.content.export/1`, exactly |
| `lib/signer.mjs`, `lib/trust.mjs` | which key may sign, and the root-signed `trust.json` |
| `lib/check.py`, `lib/checker.mjs` | the bridge to the specification's checker |
| `owner/` | the operator's two scripts |

## Licence

GPL-3.0-or-later. Copyright Minice. The files under `vendor/` keep their
sources' licence, which is the same.
