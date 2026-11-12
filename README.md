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
   - signs both with the kind's current key, under the domains
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

- The **current** private key of a kind is the single secret
  `ASTRA_<KIND>_SIGNING_KEY` of the environment `publish-<kind>`. It is read
  by one step of that kind's leg; that step reaches no network.
- The **next** private key stays offline with the operator. It is not a
  secret of any environment here, and the signer refuses to sign with it.
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

A stolen current key of one kind can sign that kind's two documents and
nothing else, until the kind is rotated.

## Rotating a key

Rotation is an operator act and needs no change here.

1. The operator re-signs `trust.json` so that the kind's `next` row becomes
   its `current` row and a new `next` row is added, and publishes it in
   astra-registry. Clients and the service already accept both keys of the
   earlier `trust.json`, so documents signed with either verify during the
   change.
2. The operator runs `owner/secrets.sh <keys-dir> --rotate <kind>`. It
   derives the public half of the private key locally, uploads the key only
   if it is the one `trust.json` now names current for that kind, and prints
   the kind, the key id and `match` or `mismatch`.
3. The next run signs both of the kind's documents under the new current
   key. Until step 2 the legs of that kind fail (the old key is no longer
   current) and the kind keeps its last signed pair. Do step 2 straight
   after step 1: an index stays valid for up to seven days, but a client
   treats a withdrawn document as stale 26 hours after it was signed.

## Setting the repository up

Both scripts are run by the operator, with `gh` signed in as an administrator
of the repository. Neither is run by a workflow.

```sh
owner/create.sh                 # environments (main only), rulesets for main and data; prints the repository id and owner id
owner/secrets.sh <keys-dir>     # each kind's current key into its environment
```

The repository id and owner id that `create.sh` prints are the ones the
service pins. An optional repository variable `CONTENT_SERVICE_URL` points
`work` at another service base (https only); the audience does not change.

## Working on it

```sh
node --test test/        # Node >= 22 and python3 >= 3.11; no network, no dependencies
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
| `lib/signer.mjs`, `lib/trust.mjs` | the current key and the root-signed `trust.json` |
| `lib/check.py`, `lib/checker.mjs` | the bridge to the specification's checker |
| `owner/` | the operator's two scripts |

## Licence

GPL-3.0-or-later. Copyright Minice. The files under `vendor/` keep their
sources' licence, which is the same.
