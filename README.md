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
   elsewhere. Each answer is written to a scratch file, held to the export
   schema, to freshness and to the kind's document schemas and rules, and
   only then copied where the job's artifact is taken from; an answer that
   fails never becomes an artifact.
2. Then each kind goes through three jobs, each on a fresh runner of its
   own. What passes from `prepare` to the later jobs is an artifact of
   fixed file names, admitted file by file (name, regular file, size bound)
   before anything in it is read. What passes from `sign` to `publish` is
   one line of job output per kind: the result and the two signatures,
   never a signed document. Artifacts of a public repository can be
   downloaded by anyone, and a signed document must not be one before
   `publish` has checked it. Nothing else crosses: no variable, no file on a
   shared disk.

   | job | holds | does |
   |---|---|---|
   | `prepare` | a token that can only read | reads the answer and the kind's last signed pair on `data`, runs the specification's checker, uploads `prepared-<kind>`: the two **unsigned** bodies, an order and the `trust.json` it used |
   | `sign` | **the kind's key**, and a token with no permission at all | a fresh checkout of the same commit, a download of `prepared-<kind>`, **one** Node command (`bin/sign.mjs`) that starts no process and opens no connection; its job output is the result and the two signatures |
   | `publish` | a token that can write contents, and no key | proves what was signed is what was prepared and verifies, then one commit on `data`, pushed forward; one kind at a time |

   The code that parses bytes the service chose, and the specification's
   checker, run in `prepare` and `publish`, never in the job that has the
   key. The key job is in the kind's environment `publish-<kind>`; it can
   neither write this repository nor mint an OIDC token
   (`permissions: {}`), and it runs no setup action, no Python and no git of
   its own.

   `prepare` refuses the kind unless all of this holds:
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

   `sign` signs both with the kind's key (see Keys), under the domains
   `astra.<kind>.index/1` and `astra.<kind>.withdrawn/1`, and only bodies
   that are canonical JSON for that kind and the order's second, and only
   when that second is its own clock: no more than 15 minutes behind and
   one minute ahead (`E_ORDER_CLOCK`). The preparing job's word for the time
   is not taken: a second months ahead, once signed, would freeze the kind
   behind every client's serial floor until `trust.json` expired. The key
   must be valid both at that second and at the job's clock.

   `publish` rebuilds each signed document from the prepared body and the
   key job's signature, checks the order's second against its own clock
   (the same window) and against the serial of the pair it verified on
   `data` itself (later, never equal or earlier), and checks that each
   document is exactly the body that was prepared, carries one signature,
   and verifies under the kind's key from
   `trust.json` (read afresh, not the copy in the artifact), by this
   repository's code and again by the specification's verifier, and that
   `data` still holds the pair the kind was prepared against. Only then are
   `registry/v1/<kind>/index.json`, `registry/v1/<kind>/withdrawn.json` and
   `state/<kind>.json` written and committed in one commit. `data` only
   moves forward.

   A kind whose answer is the one signed less than six hours ago, under the
   key the job holds, is left as it is.
3. The plugins service mirrors `data`, verifies each pair again exactly as a
   client does, and serves it.

A kind that cannot be signed fails its own job and keeps its last signed
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
  kind's `sign` job, the job's one Node command, which reaches no network.
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

### When a kind cannot be signed over what data holds

The signer builds on a kind's last signed pair only after verifying it, and
refuses a kind whose files were removed from `data`. Two codes stop a kind
for good, until an administrator acts; every other kind goes on being signed
and the stopped kind's last pair stays served.

| code | what `data` holds |
|---|---|
| `E_PREVIOUS_UNVERIFIED` | a pair for the kind that no key of the kind in `trust.json` verifies |
| `E_PREVIOUS_MISSING` | none (or only part) of the kind's three files, although a commit on `data` once held them |

Neither has a switch that starts the kind empty, and none should be added:
the kind's withdrawn rows live in that pair, and a kind started empty would
drop every one of them, a confirmed removal under the content rules
included. In the commands below, `K` is the kind and the clone is of this
repository, by an administrator:

```sh
REPO=mihailinl/astra-content-catalogue K=commands
git clone -q -b data "https://github.com/$REPO" data && cd data
git log --first-parent --format='%h %an %s' -- "registry/v1/$K" "state/$K.json" | head
```

Every commit the workflow made is by `astra-content-catalogue` and reads
`sign <kind>: issued_at <second> under <key id>`. Anything else on `data`
was written by somebody else, and is the first thing to understand.

**`E_PREVIOUS_UNVERIFIED` after a key ceremony.** A ceremony that removed
**both** keys a pair could have been signed with (it should not be needed:
rotate first, and the key that signed last stays in `trust.json`) leaves a
pair nothing can verify. Nothing on `data` changes; the administrator names
the pair, by the SHA-256 of its two files, in `recovery.json` on `main`:

```sh
git show "HEAD:registry/v1/$K/index.json" | sha256sum
git show "HEAD:registry/v1/$K/withdrawn.json" | sha256sum
# in a clone of main: add {"kind": K, "index_sha256": …, "withdrawn_sha256": …} to "accept", then
git commit -m "recovery: build $K on its pair at data <commit>" recovery.json && git push origin main
```

`main` is updated by administrators only, so the entry is a reviewed
statement by a person. No ruleset is disabled. The next run carries that
pair's rows, keeps its serial as the floor, and signs the kind with the key
the environment holds; from then on the pair on `data` verifies and the
entry matches nothing, so remove it in a later commit. Nothing is lost.

**`E_PREVIOUS_MISSING`, or an `E_PREVIOUS_UNVERIFIED` pair that the workflow
did not write.** Somebody other than the workflow wrote `data`. Treat it as
a compromise of whatever could write it (the `publish` job's token, or the
account of somebody who can push this repository) and deal with that first. Then put the kind's last
pair the workflow signed back, as a new commit on top: `data` moves forward
only, and a forced update stays refused for everybody.

```sh
GOOD=<the last commit by astra-content-catalogue that signed K>
git checkout "$GOOD" -- "registry/v1/$K" "state/$K.json"
git -c user.name=operator -c user.email=operator@invalid commit -m "restore $K as signed at $GOOD"
git push origin HEAD:data
```

This repository belongs to a personal account, so `data` carries only the
ruleset `data: forward only`, and anybody who can push the repository pushes
that commit as it is; no ruleset is touched. (Owned by an organisation,
`owner/create.sh` also sets `data: written by the workflow only`; then
disable that one ruleset around the push, with
`gh api --method PUT "repos/$REPO/rulesets/$ID" -f enforcement=disabled` and
`-f enforcement=active` after, where `ID` is its id from
`gh api "repos/$REPO/rulesets"`, or run `owner/create.sh` again to set it
back.)

What is lost: nothing the workflow signed. The restored pair is the one the
service last accepted, so its serial is the service's floor and the next run
signs above it; any commit written in between is left in history and not
served. If the restored pair no longer verifies (a key ceremony happened
since), follow the first case for it as well.

## What protects the keys, and what GitHub cannot enforce

| what must hold | what enforces it |
|---|---|
| a kind's key is read only by that kind's `sign` job | the secret belongs to the environment `publish-<kind>`; an environment deploys from the branch `main` only |
| the code that job runs is the reviewed code on `main` | the ruleset `main: updated by administrators only`; the job checks out the run's own commit afresh |
| nothing an earlier job did reaches the key job but its artifact | jobs run on separate runners; the key job admits the artifact file by file and reads nothing else; no job writes `GITHUB_ENV` or `GITHUB_PATH` |
| `data` only moves forward | the ruleset `data: forward only`; no bypass, the workflow and administrators included |
| `data` is written only by the workflow | not enforced on this repository: see "What remains" |
| the service is asked only by this workflow on `main` | the service pins the token's repository id, workflow, ref and environment |

Two things GitHub does not offer, and what stands in for them:

- **A token cannot be limited to one branch.** The `publish` job's token has
  `contents: write`, which it needs to push `data`; the same token could
  push `main`. Nothing in the workflow file can prevent that. The ruleset on
  `main` does: only the repository's admin role may update `main`, and a
  workflow token is not an administrator. The key job's own token has no
  permission at all. `owner/secrets.sh` refuses to upload any key until that
  ruleset exists and is active, and until the kind's environment deploys
  from the branch `main` and from nothing else.
- **A secret cannot be read back.** Nobody can ask GitHub which key an
  environment holds. So the signer derives the public half of whatever key
  it is given and refuses a key that is not one of the kind's two; and
  `owner/secrets.sh` reads which key signed the kind's documents on `data`
  and refuses to put a current key over a rotation in progress.

### What remains

The key no longer shares a runner with anything that reads the service's
bytes: the job that holds it starts on a fresh machine, from a fresh
checkout, with one artifact of four named files as its only input. What
still stands beside the key:

- **The code on `main`, and the actions it pins.** The key job runs this
  repository's code at the run's commit, the runner's own Node, and three
  actions (`checkout`, `download-artifact`) pinned by commit. Whoever can change `main` or those pins can read the key. That is
  the admin role, through the ruleset.
- **GitHub.** Its secret store, its runners and its artifact storage are
  trusted; nothing here can check them.
- **What `prepare` hands over.** A `prepare` job that was taken over (say,
  through a flaw in the checker reached by the service's bytes) chooses the
  bodies the key job signs. The key job still signs only canonical bodies of
  that one kind, for that one second, under that kind's domains, and
  `publish` runs the specification's verifier again before anything reaches
  `data`. Such an attacker gains what a compromised service already has.
  The signatures leave the key job as a job output, not as an artifact, so
  a document signed and then refused by `publish` is not published
  anywhere.
- **Artifact names are not isolated per kind.** Every job of a run can
  upload an artifact under any name, so a taken-over `prepare` leg of one
  kind could upload `prepared-<another kind>` before that kind's own leg
  does (whose upload then fails, and the run goes red). The key job signs
  an artifact only when its order names the job's own kind, so the key of
  kind A is never used on an order for kind B; but within kind A it signs
  what that artifact holds, like any `prepare` that was taken over (above).
  Which job uploaded an artifact cannot be checked from the key job: the
  artifact API needs a token and a connection, and the key job has
  neither.
- **Who can push `data`.** GitHub accepts no app as a ruleset's bypass
  actor on a repository owned by a personal account, so the ruleset that
  would let only the workflow write `data` cannot be set here
  (`owner/create.sh` says so and sets the other three). Besides the
  workflow's `publish` job, whoever can push this repository (today: its
  owner alone) can move `data` forward; nobody can force it or delete it.
  That costs availability at most, never a forged document: every byte the
  service serves from `data` must verify under the kind's keys in the
  root-signed `trust.json`, and the signer itself builds only on a pair
  that verifies. An older valid pair pushed back is a rollback, and the
  service's serial floor per document (SERVE-116) refuses it and alarms. A
  deploy key would close this at the price of one more secret to guard; it
  is not used.
- **Two compromises together.** An attacker who can write `data` *and*
  controls the service can put an older pair of a kind back on `data` (it
  verifies: it was signed here) and have the service omit the withdrawn
  rows added since. The signer carries forward only what the pair on `data`
  holds, so those rows leave without a lift and without a failed run. One
  of the two alone cannot do it: the service alone cannot drop a published
  row (the row is kept and the run fails), and `data` alone cannot drop one
  either (the service states the rows afresh). The outside anchor is the
  service's serial floor per document (SERVE-116): an honest service
  refuses, and alarms on, a pair below the floor it already served, so the
  restored pair is noticed unless the service itself is the second
  compromise.

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
| `bin/prepare.mjs`, `bin/sign.mjs`, `bin/verify.mjs` | the commands of the `prepare`, `sign` and `publish` jobs; `sign.mjs` is the one with the key |
| `lib/pipeline.mjs` | prepare and verify: the order of checks |
| `lib/keystep.mjs` | what the job with the key does, and all it can import |
| `lib/workdir.mjs` | the two artifacts: their file names, size bounds, and how they are admitted |
| `lib/recovery.mjs`, `recovery.json` | pairs an administrator has named to build on (see "When a kind cannot be signed over what data holds") |
| `lib/state.mjs` | the last signed pair on `data`, proven before use |
| `lib/carry.mjs` | which earlier rows are kept, and how a lift names a row |
| `lib/export.mjs` | `astra.content.export/1`, exactly, and fresh |
| `lib/signer.mjs`, `lib/trust.mjs` | which key may sign, and the root-signed `trust.json` |
| `lib/check.py`, `lib/checker.mjs` | the bridge to the specification's checker |
| `owner/` | the operator's two scripts |

## Licence

GPL-3.0-or-later. Copyright Minice. The files under `vendor/` keep their
sources' licence, which is the same.
