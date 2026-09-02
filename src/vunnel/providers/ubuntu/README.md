# Ubuntu provider

## Overview

This provider ingests Canonical's OSV to get vulnerability data about Ubuntu.
However, this data is incomplete in 4 ways:

1. It does not cover Ubuntu versions that no longer receive any support
2. It does not mark CVEs as "won't fix" when Canonical has decided not to
   publish a fix.
3. It does not report when a fix became available
4. It does not list vulnerabilities for packages in base Ubuntu that are only
   fixed in ESM.

To work around the first limitation, this provider relies on the
`normalized_cve_data` directory written into the cached workspaces by previous
versions of the provider, which cloned down the ubuntu-cve-tracker git repo and
examined the history to learn what the vulnerable status of packages in EOLed
Ubuntu versions was before it was removed.

To work around the second, this provider also downloads Canonical's OpenVEX
feed annotates the OSV data with "won't fix" information from the OpenVEX.

To work around the third limitation, this provider builds an in-memory
overlay from the USN records in the OSV tarball (`osv/usn/**`) — each USN's
top-level `published` field is the moment Canonical pushed the patched
package to the archive, i.e. the real fix-ship date. The overlay supplies
this as a high-confidence candidate to the fix-date finder so that, e.g.,
turning on Pro ingestion doesn't make every Pro fix look like it shipped
today (which is what the legacy "first-observed in grype-db" heuristic
would record on the first build to see Pro data). The grype-db-observed
fix-date cache remains the fallback for the ~23% of fix tuples that don't
have a matching USN entry (FIPS / Realtime / Nvidia-BlueField tiers don't
ship via USN).

To work around the fourth limitation, this provider infers the existence of a
"wont-fix" record for packages that are fixed in Ubuntu Pro but not mentioned
in regular Ubuntu of the same version number.

Because presently supported Ubuntu versions are expected to disappear from the
OSV data after they reach EOL, the following strategy is used:

1. The OSV data is downloaded.
2. The OSV data is sharded by ecosystem, so that there is a cache per ubuntu
   version.
3. On subsequent runs, a version's fragment is rewritten from today's tarball
   whenever that ecosystem string appears in it, and left untouched otherwise —
   so a release that drops out of the feed keeps emitting its last known state.
4. Which source is *served* for a release — its OSV fragment or the frozen
   `normalized-cve-data` cache — is a separate decision, keyed on live-record
   density rather than on fragment existence.

The two caches have deliberately different lifecycles, and it is worth being
precise about which one "the cache stands indefinitely" applies to:

| Cache | Written by the provider? | Lifecycle |
|---|---|---|
| `input/normalized-cve-data/` | **Never** | Kept forever, shadowed whenever OSV has live data for the release |
| `input/fragments/*.db` | Every run, per ecosystem | Rewritten wholesale (`DELETE_BEFORE_WRITE`) for each ecosystem present in today's tarball; frozen only for ecosystems absent from it |

So the keep-forever-and-shadow model holds for `normalized-cve-data` but NOT
for fragments: a fragment is replaced, not layered. That distinction is the
whole reason step 4 exists. Because Canonical leaves a residue of
already-`withdrawn` records behind instead of dropping an EOLed ecosystem, the
condition in step 3 still fires for a release that has stopped being published,
and the fragment gets rewritten from residue — see "Known remaining work"
below. Step 4 is what keeps such a release serving usable data anyway, by
declining to let a residue-only fragment shadow `normalized-cve-data`. See "How
the provider decides a release is OSV-covered" below.

## Data sources

The provider reads four things, in priority order:

| Source | URL / path | Role | Lifecycle |
|---|---|---|---|
| OSV CVE feed (`osv/cve/**`) | `https://security-metadata.canonical.com/osv/osv-all.tar.xz` | Authoritative ranges + fix versions for currently-tracked releases | Streamed each run, never extracted to disk |
| OSV USN feed (`osv/usn/**`) | same tarball | Authoritative fix-ship dates (USN.published) — see "USN fix-date overlay" below | In-memory index built each run; not persisted |
| OpenVEX feed | `https://security-metadata.canonical.com/vex/vex-all.tar.xz` | Fix disposition (won't-fix vs other) — see "Why VEX" below | Streamed each run; in-memory index, not persisted |
| `input/normalized-cve-data/` | local | Releases the live feeds carry no usable data for: precise → mantic, plus oracular and plucky (see "How the provider decides a release is OSV-covered") | Frozen; populated by the v3 provider, kept untouched after v3's removal |
| (fix-date cache) | `input/grype-db-observed-fix-dates.db` | Cross-provider fallback for fix dates when no USN advisory shipped the fix | Refreshed each run |

USN records are **not emitted** as their own envelopes — the previous provider
didn't surface them either. They're used purely as a metadata source: the
USN→CVE join supplies real fix-ship dates that the CVE records themselves
don't carry. Emitting USN-keyed advisories alongside CVE entries is a
possible future enhancement.

## Output: per-ecosystem fragments + legacy passthrough

```
data/ubuntu/
  input/
    osv-all.tar.xz                # today's download (overwritten each run)
    vex-all.tar.xz                # today's download (overwritten each run)
    fragments/                    # persistent, load-bearing
      ubuntu-14.04-lts.db
      ubuntu-18.04-lts.db
      ubuntu-20.04-lts.db
      ubuntu-pro-16.04-lts.db
      ubuntu-pro-fips-updates-20.04-lts.db
      …                           # one per distinct ecosystem string
    normalized-cve-data/          # frozen at-cutover EOL data (phase 1)
    grype-db-observed-fix-dates.db
  results/
    results.db                    # mixed-schema (OSV + OS) output
```

Each fragment file is an envelope-shaped `results.db` containing only
one ecosystem's slices. Envelope identifier is
`{ecosystem-slug}/{cve-id-lowercase}`, e.g.
`ubuntu-20.04-lts/ubuntu-cve-2024-1234`.

### Why per-release fragments when Canonical publishes per-CVE

OSV records describe a CVE across N releases in one document. We
re-shard into one envelope per (release, CVE) for two reasons:

1. **Survive EOL transitions without operator action.** When a release
   genuinely drops out of the OSV feed, its fragment file stops being
   rewritten. The fragment persists, frozen at the last-known state, and
   subsequent runs continue to emit it. There is no hardcoded EOL list
   and no manual snapshot step — the on-disk set of fragments IS the
   list of releases the provider knows about. When 25.10 EOLs the same
   machinery handles it.

   The caveat, and it is a large one: Canonical mostly *doesn't* drop a
   release out of the feed. It keeps emitting a shrinking residue of
   `withdrawn` records, which `DELETE_BEFORE_WRITE` happily writes over
   the good fragment. So the freeze is not automatic, and "the fragment
   exists" is not the same claim as "the release is still published."
   See "How the provider decides a release is OSV-covered".

2. **Match the downstream contract.** grype's dpkg matcher resolves
   per-namespace via `search.ByDistro`. Per-ecosystem fragments map 1:1
   to that contract; the alternative (multi-release records the
   transformer slices) just moves the same work downstream.

### Why fragments stay separate for Pro/FIPS/Realtime/etc.

Today's tarball publishes 33 distinct ecosystems:

- Base: `Ubuntu:14.04:LTS` through `Ubuntu:26.04:LTS`, plus interim
  releases like `Ubuntu:25.10`
- Subscription tiers: `Ubuntu:Pro:18.04:LTS`,
  `Ubuntu:Pro:FIPS-updates:20.04:LTS`,
  `Ubuntu:Pro:Realtime:22.04:LTS`, `Ubuntu:Nvidia-BlueField:22.04:LTS`,
  etc.

We keep these as separate fragments rather than collapsing them into
the base release. Different tiers have different fix policies and
different CVE coverage; downstream is expected to gain
subscription-tier-aware matching eventually, and collapsing here would
be a one-way decision. Cost: ~2.5 GB of additional fragment storage
across 20 sub-ecosystems.

## How the provider decides a release is OSV-covered

There is exactly one question to answer per release: is this release
being served by OSV, or does it need to come from an older source? The
answer decides whether the legacy `normalized-cve-data` passthrough emits
for that release at all — `Parser._osv_covers_legacy_namespace(ns)`.

### Three service tiers

| Tier | Served from | Members today |
|---|---|---|
| Actively published | live OSV feed | jammy, noble, focal, bionic, trusty/ESM, xenial/ESM, questing, plus Pro/FIPS/Realtime/BlueField |
| Aged out after the OSV cutover (2026-06-24) | frozen fragment on disk | *none yet* — questing EOLed ~2026-07 but is still published, at 13,218 live records |
| Already EOL before the cutover | `input/normalized-cve-data/` | precise → mantic, plus oracular (EOL ~2025-07) and plucky (EOL ~2026-01) |

Plucky and oracular both predate the cutover, so they belong in the third
tier. They were being assigned to the first, which is the bug this
section exists to explain.

### Why "does the fragment exist" was the wrong test

The original predicate asked whether `ubuntu-<version>.db` (or
`ubuntu-<version>-lts.db`) existed on disk. Because
`DELETE_BEFORE_WRITE` creates a fragment for every ecosystem string the
tarball mentions, that is equivalent to asking whether the ecosystem
string appears *anywhere* in the tarball — at any density, in any state.

Canonical does not stop emitting an EOLed release. It leaves behind a
residue of already-`withdrawn` records, so the ecosystem string survives
and the fragment gets rewritten from the residue. Records per ecosystem
in today's tarball (2026-09-02):

```
27568 (  695 withdrawn)  Ubuntu:24.04:LTS
13365 (  147 withdrawn)  Ubuntu:25.10
  184 (  181 withdrawn)  Ubuntu:25.04     <- plucky
  157 (  153 withdrawn)  Ubuntu:24.10     <- oracular
   15 (   15 withdrawn)  Ubuntu:26.04     <- residue from the pre-LTS ecosystem relabel
```

The residue exists because a retracted record is never regenerated: it
keeps its stale plucky `affected[]` entry forever.

Consequence: the provider emitted **3** records for `ubuntu:25.04` and
**zero** for `ubuntu:24.10`, while `normalized-cve-data/` held ~25,575
CVEs with plucky patches (9,778 `released`, 78,463 `not-affected`
entries, 6,325 `needed`, 728 `ignored`) — every one of them suppressed
because the existence test concluded OSV had plucky covered. Canonical's
own OVAL export still carries plucky's terminal state, at 9,157 CVE
definitions, so the OSV export dropping it looks like an upstream defect
worth reporting.

### The density test

`_osv_covers_legacy_namespace` now asks how many **live**
(non-`withdrawn`) records the release's base fragment holds, and counts
the release as covered only at `_MIN_LIVE_RECORDS_FOR_COVERAGE = 100` or
more. `Parser._fragment_live_record_count()` does the counting;
`Parser._osv_covered_versions()` caches the per-run answer and is reset
at the start of `_write_fragments`. As before, only base-ecosystem
filenames are considered, so a Pro fragment never establishes coverage
for its base release.

Discarding withdrawn records is uniform and correct because `withdrawn`
is a **whole-record** OSV field, not a per-ecosystem one. All 181 of
plucky's withdrawn records are withdrawn for every other release they
list too — 148 of them also appear in `ubuntu-24.04-lts.db`, withdrawn
there as well. Noble discards its own 695 the same way.

The threshold sits ~25x clear of both sides of the gap:

| Fragment | Live records |
|---|---|
| `Ubuntu:26.04` | 0 |
| `Ubuntu:25.04` (plucky) | 3 |
| `Ubuntu:24.10` (oracular) | 4 |
| ecosystem-rename stubs: `Ubuntu:22.04:LTS:for:NVIDIA:BlueField`, the two `Ubuntu:Pro:*:Realtime:Kernel` variants | 1–2 |
| `Ubuntu:Pro:26.04:LTS` — the smallest healthy fragment | 986 |
| everything else | 8,000–35,000 |

Counting via SQL `not like '%"withdrawn":%'` costs 14.3s across the real
33-fragment, ~7 GB set and matches full JSON parsing exactly, so the cheap
test is also the correct one.

### Two subtleties, both easy to regress

1. **Coverage is computed from the fragments on disk, not from today's
   tarball.** A release that has genuinely aged out of the feed keeps a
   healthy frozen fragment and must still count as covered, so legacy
   does not shadow it. Counting from the tarball instead would wrongly
   mark every frozen release uncovered — that is the middle service tier
   above, and not shadowing it is the entire point of freezing
   fragments.
2. **Coverage keys on live-record count only, never on record age or
   `modified` staleness.** A healthy frozen fragment is stale by
   construction, so age cannot distinguish it from a degenerate residue
   fragment. Published timestamps are especially untrustworthy here:
   Canonical's OVAL directory listing shows plucky "Modified
   2026-08-31", while the `<oval:timestamp>` inside that same file reads
   2025-11-27 and the file contains no 2026 CVEs at all. Publication
   mtimes are republish artifacts, not content freshness.

### Misclassification here is additive, not destructive

If a live release is wrongly marked uncovered, legacy emits alongside
OSV and OSV still wins per-CVE, because OSV is yielded last (see
"Operational invariants"). The failure mode is redundant rows, not lost
data. That layering is what makes a count-with-clearance heuristic an
acceptable way to answer the coverage question at all.

### Known remaining work

This change fixes the *shadowing*, not the fragment clobbering that
caused it. `_write_fragments` still rewrites a fragment from whatever the
tarball carries, residue included, so a fragment can still silently lose
most of its rows. A follow-up will persist a per-ecosystem manifest, so
that the decision to freeze a fragment is recorded rather than inferred
from the fragment's contents on every run.

## Per-run flow

```
Provider.update()
 └─ Parser.get()
      ├─ _download_archive()       # stream osv-all.tar.xz to disk
      ├─ _download_vex_archive()   # stream vex-all.tar.xz to disk
      ├─ fixdater.download()
      ├─ _load_vex_overlay()       # build in-memory wont-fix index from VEX
      ├─ _load_usn_overlay()       # build in-memory (eco, pkg, fix-ver) → USN.published index
      ├─ _write_fragments(overlay):
      │     reset the _osv_covered_versions() cache
      │     for each osv/cve/**/*.json (streaming, no extraction):
      │         slice_by_ecosystem(record)        # group affected[] by ecosystem
      │         _annotate_wont_fix(...)           # stamp anchore.status from VEX
      │         for each slice:
      │             open fragment writer (lazy, DELETE_BEFORE_WRITE)
      │             insert envelope
      ├─ yield from _iter_normalized_cve_data()   # legacy first
      │     skip releases where _osv_covers_legacy_namespace(ns);
      │     coverage = base fragment holds >= 100 live records
      └─ yield from _iter_fragments()             # OSV second
            for each base ecosystem:
              yield real base envelopes (patch_fix_date applied;
                                         USN overlay provides authoritative
                                         fix-ship dates as accurate candidates)
              merge inferred wont-fix entries from sibling Pro fragments
                into existing envelopes, or synthesize new ones
```

Three annotations live in `affected[].database_specific.anchore`:

- `fixes[]` — `{version, date, kind}` populated by `patch_fix_date` at yield
  time. Source priority: (1) USN overlay (`USN.published`, marked
  accurate=True; covers ~77% of fix tuples across the live feed and 88–100%
  of plain-Pro tiers), (2) grype-db-observed first-observed cache, (3)
  CVE-record `published` date as a last-resort low-confidence fallback.
  Applied **at yield time** so improvements to either USN data or the
  fix-date cache flow through to frozen fragments on the next run without
  rewriting them.
- `status` — `"wont-fix"` when Canonical's VEX feed marks this
  `(cve, distro, source-pkg)` as won't-fix. Applied **at write time**,
  baked into the fragment. When a release later EOLs and VEX stops
  carrying it, the frozen fragment retains the disposition.
- `inference` — when a base wont-fix entry was synthesized from a
  Pro-only-fix record (see next section). Applied **at yield time** on
  synthesized base entries. Carries `kind: "pro-only-fix"` and
  `source_ecosystems` (the Pro ecosystems whose presence triggered the
  inference) — gives downstream a precise join key for future
  Pro-fix-suggestion behavior.

These have deliberately different update semantics. Fix dates can be
refined retroactively from new tracking data; the won't-fix status is a
"what Canonical decided at this moment" snapshot that must survive the
release leaving both upstream feeds; the inference is recomputed every
yield from current Pro data, so frozen base fragments still pick up
newly-published Pro-only fixes after base EOLs.

## Pro-only-fix → base wont-fix inference

Canonical encodes "this CVE will only be fixed in Pro/ESM, not base
Ubuntu" by **omitting the base ecosystem** from the OSV record's
`affected[]` while listing the Pro tier. E.g. CVE-2018-20796 lists
`Ubuntu:Pro:20.04:LTS / glibc` but no `Ubuntu:20.04:LTS / glibc` — the
intent is "base focal users won't get a fix; only Pro subscribers
will." v3 captured this via `status: ignored` on base in the tracker;
OSV drops the signal entirely.

At yield time, for each base ecosystem fragment we look at sibling
plain-Pro fragments (`Ubuntu:Pro:X.YY:LTS` only — see below). For any
`(CVE, source-package)` tuple Pro lists but base doesn't, we
synthesize a base wont-fix entry. Synthesized entries are merged into
the existing base envelope when one exists; they become a new envelope
when base has no entry for that CVE at all.

**Why only plain Pro, not FIPS/Realtime/Nvidia-BlueField:** plain Pro
packages are byte-identical to base packages while base is supported,
then diverge via ESM-backported patches — same vulnerable code, so the
inference is sound. FIPS rebuilds specific packages against
FIPS-validated cryptographic modules (different crypto code paths);
Realtime is the PREEMPT_RT kernel (different locking/scheduling code);
Nvidia-BlueField is a separate SmartNIC OS. A CVE in those builds
doesn't reliably imply the same CVE on base, so we don't infer from
them.

**Why at yield time, not write time:** consider the post-EOL scenario.
Base 24.04 eventually drops out of OSV; its fragment freezes. Pro:24.04
is still tracked. A new CVE-X gets a Pro-only fix. Yield-time inference
sees the fresh Pro:24.04 record alongside the frozen base 24.04
fragment and produces a synthetic base wont-fix entry — base 24.04
users get the disclosure without us rewriting the frozen base data. A
write-time inference would have to either overwrite the frozen base
fragment (losing pre-EOL real data) or special-case the wipe-and-rewrite
semantics; both are worse.

**Provenance for future grype behaviors:** the synthesized entry's
`anchore.inference.source_ecosystems` carries the Pro ecosystems that
triggered it. Downstream can use this as a join key to look up the Pro
fix version for "vulnerable, fix available via Pro upgrade" presentation
when a user opts in to Pro-fix suggestions.

## USN fix-date overlay

Canonical's OSV CVE records don't carry per-fix dates — the record's
top-level `published` is the *vulnerability* disclosure date, often
months or years before the fix actually shipped. VEX doesn't help either:
spot-checked against real records, statement timestamps on `status:
"fixed"` entries are CVE-publish dates, not fix-ship dates (e.g., a
chromium 65 fix carries a timestamp from 2012).

The fix-ship date lives in the USN's top-level `published` field. Real
example: CVE-2023-38545 (curl) → USN-6429-1 published `2023-10-11T11:34:51Z`,
which is the public coordinated disclosure date.

The provider streams `osv/usn/**` and builds an in-memory index keyed by
`(ecosystem, source-pkg, fixed-version) → earliest USN published date`.
At yield time, when `patch_fix_date` walks each `fixed:` event, the USN
overlay's date is supplied as a high-confidence (`accurate=True`)
candidate to `fixdater.best()`, which beats first-observed when both are
present. The grype-db-observed first-observed cache remains the fallback.

**Why this matters now**: when we add Pro ingestion (or any data shape
v3 didn't carry), the grype-db-observed cache won't have history for the
new rows. Without the USN overlay, those fixes would all date to the
first build that captured them — i.e., "the day we turned on Pro." With
the overlay, we read the real fix-ship date out of the USN that shipped
it, regardless of how long ago.

**Coverage** measured against today's full tarball: 77% of CVE fix
tuples have a matching USN tuple overall. Plain-Pro coverage runs
88–100% across all releases — exactly the regime the cutover stresses.
FIPS-updates / Realtime / Nvidia-BlueField have low USN coverage (those
tiers ship through non-USN channels); they fall through to first-observed
without regression. The 23% USN-miss case has no impact vs. the prior
behavior — the overlay only adds dates, never removes them.

**Date precedence inside `fixdater.best()`**: candidates with
`accurate=True` are upper-bound filters; the most-accurate, earliest
remaining candidate wins. The USN overlay's `(date, kind="advisory",
accurate=True)` candidate beats first-observed when both are present and
beats CVE.published (which is `accurate=False`) unconditionally.

## Why OpenVEX (not just OSV)

Canonical's OSV publication intentionally collapses six tracker
statuses into one shape:

| ubuntu-cve-tracker status | OSV representation |
|---|---|
| DNE, not-affected | (absent from `affected[]`) |
| released | `affected[]` with `fixed:` event |
| **needs-triage, needed, ignored, pending, deferred, in-progress** | **`affected[]` with `events: [{"introduced": "0"}]` — indistinguishable** |

Documented at
[documentation.ubuntu.com/security/security-updates/osv/](https://documentation.ubuntu.com/security/security-updates/osv/).
The collapse loses the "won't fix" signal — a single sentinel `affected`
entry could mean Canonical is still triaging or has decided not to
patch.

The same data in OpenVEX preserves granularity. For `status: "affected"`,
the `action_statement` field uses four canonical opening phrases:

```
"...decided to not fix it..."        → wont-fix (ignored, won't patch)
"...is no longer supported..."       → wont-fix (EOL flavor)
"...needs fixing"                    → not-fixed (will be patched eventually)
"...needs fixing, and...actively..." → not-fixed (active work)
```

The provider downloads VEX, prefix-matches `action_statement` against
the won't-fix openings, and indexes the resulting
`(cve_id, distro_label, source_package)` tuples. At fragment-write time
each OSV slice's `(cve, distro, source-pkg)` is looked up; matches get
`affected[].database_specific.anchore.status = "wont-fix"`. The grype
v6 ubuntu transformer reads that annotation and emits `WontFixStatus`,
producing the `(won't fix)` annotation users see in scan output.

The join key is the PURL `distro=` qualifier (e.g. `distro=noble`,
`distro=esm-infra/jammy`). Both OSV and VEX embed it identically — no
codename/version translation needed.

## Why `normalized-cve-data` is still load-bearing

Live VEX has **the same coverage gap as live OSV**: only currently-
tracked releases are present (jammy, noble, focal, bionic, trusty/ESM,
xenial/ESM, questing, plus Pro/FIPS/etc.). Releases that were EOL
before Canonical's OSV/VEX feeds launched — precise, quantal, raring,
saucy, utopic, vivid, wily, yakkety, zesty, artful, cosmic, disco,
eoan, groovy, hirsute, impish, kinetic, lunar, mantic — are absent.
Oracular and plucky are nominally present but effectively absent: what
remains of them is `withdrawn` residue (see "How the provider decides a
release is OSV-covered"), so for practical purposes they belong on that
list too.

The v3 provider's `normalized-cve-data/` cache covers those releases
(it was populated from `ubuntu-cve-tracker` git history before v3 was
retired). Its scope runs further than the pre-cutover set: the cache
is current to ubuntu-cve-tracker rev `c156268` and carries questing
(1.87M patch entries) and resolute (1.75M) as well as plucky and
oracular — so for the releases OSV still publishes, the cache is
redundant rather than missing, and the coverage predicate is what keeps
it from shadowing live data. The new provider reads it via the vendored
`map_parsed` from `parser_legacy.py` and emits OS-schema envelopes for
releases not already covered by an OSV fragment.

`normalized-cve-data` records carry `status: "ignored"` directly, which
`map_parsed` already converts to `FixedIn[].VendorAdvisory.NoAdvisory =
True` — grype's OS transformer renders this as `WontFixStatus`. So the
EOL slice already preserves won't-fix without any VEX involvement; the
overlay only matters for the OSV path.

Until Canonical publishes EOL data in some refreshable format,
`normalized-cve-data/` stays in `input/`. It is frozen forever — the
provider never writes to it.

## Operational invariants

- **`input/` is load-bearing.** `fragments/` carries frozen OSV state
  for releases no longer in the feed; `normalized-cve-data/` carries
  pre-cutover EOL data. Losing either is unrecoverable. `Provider.__init__`
  enforces this via `disallow_existing_input_policy(config.runtime)`
  plus an explicit check on `config.runtime.on_error.input`.
- **Don't bump `__version__` or `__distribution_version__`.** The
  framework treats version changes as workspace-clear triggers and
  would wipe `input/`. Per-envelope schema URLs (each record carries
  its own OSV or OS schema URL) are the dispatch signal downstream
  consumers gate on — a global version bump is both redundant and
  destructive.
- **Emit order is load-bearing: legacy first, OSV last.** In OSV-shaped
  output the two identifier spaces are disjoint — OSV fragment envelopes
  use `ubuntu-{slug}/ubuntu-cve-X` (hyphen-prefixed), legacy envelopes
  use `ubuntu:{X.YY}/cve-X` (colon-prefixed). With
  `downconvert_osv_to_os` on, they **do** collide: both paths emit
  `{namespace}/{cve.lower()}`. That collision is deliberate. Because OSV
  is yielded last, `INSERT OR REPLACE` lets real OSV data override
  legacy data for the same `(namespace, CVE)`. See
  `TestParserEmissionOrder` and the comment near the `get()` method.
  This layering is what makes coverage misclassification additive rather
  than destructive.
- **`compatible_schema()` is intentionally NOT implemented.** The
  parser yields `(identifier, Schema, payload)` triples directly; the
  classmethod is a per-provider filter bitnami uses to gate on schema
  version, which we don't need.

## Schema versions

Records pass through with their declared `schema_version` preserved.
Today's tarball carries 1.7.0 (~99%) plus a 1.6.3 tail (~1%, mostly
older Pro:14.04 records). Each fragment envelope's schema URL reflects
the record's own version — `OSVSchema(version=record["schema_version"])`
— so downstream sees the actual shape per record rather than a
provider-pinned constant.

## Withdrawn records

Canonical uses the OSV `withdrawn` field (6.1% of records today) for
retractions. They do **not** delete records from the tarball, so a
withdrawn CVE's `withdrawn` timestamp rides through the slicing into
each fragment payload. The grype `ubuntuStrategy` skips withdrawn
records entirely; the legacy passthrough is the only path a
withdrawn-by-OSV CVE can still reach the DB (via a frozen `results.db`
row for an EOL release).

`withdrawn` is a **whole-record** field, not a per-ecosystem or
per-`affected[]` one: a withdrawn record is withdrawn for every release
it lists. That is what makes it safe to ignore withdrawn records when
measuring whether a release is still being published. It is also the
mechanism behind the residue problem — because a retracted record is
never regenerated, it keeps listing releases Canonical stopped tracking
years ago. See "How the provider decides a release is OSV-covered".

## What grype expects

The v6 dpkg matcher queries by namespace via `search.ByDistro`. The
grype OSV transformer
([`grype/db/v6/build/transformers/osv/transform_ubuntu.go`](https://github.com/anchore/grype/blob/main/grype/db/v6/build/transformers/osv/transform_ubuntu.go))
turns each fragment envelope into the same DB row shape the legacy OS
transformer produces. Notable mappings:

- Primary ID = upstream CVE (`vuln.Upstream[0]`), not `UBUNTU-CVE-*`.
  The UBUNTU-CVE id is Canonical's internal record key; users see CVE-X
  in grype output.
- Vendor severity (`type: "Ubuntu"`) → CHMLN scheme, lowercase string.
  Matches the legacy OS transformer's ordering so OSV-sourced and
  OS-sourced rows are downstream-fungible.
- `Ubuntu:24.04:LTS` → `db.OperatingSystem{Name: "ubuntu", MajorVersion:
  "24", MinorVersion: "04", Codename: "noble"}`.
- `Ubuntu:Pro:14.04:LTS` → same shape + `Channel: "esm"`.
- `affected[].database_specific.anchore.status == "wont-fix"` →
  `Fix{State: WontFixStatus}` on the no-fix sentinel range.

## Optional: OSV → OS downconversion

For consumers stuck on a grype-db build process that pre-dates the OSV
transformer, the provider can rewrite every fragment envelope into the
v3 `{"Vulnerability": {...}}` OS-schema shape as it is yielded. Enable
it via config:

```yaml
providers:
  ubuntu:
    downconvert_osv_to_os: true   # default: true
    downconvert_emit_esm: true    # default: true; only meaningful when downconvert_osv_to_os is on
```

`downconvert_emit_esm` controls whether plain Ubuntu Pro (ESM) slices are
emitted as `ubuntu:X.YY+esm` channel records. Set it `false` for the frozen-v5
lane, whose build isn't validated against `+esm` channels — plain Pro then maps
to `None` like the sub-tiers, and only base records are emitted.

When the toggle is on:

- The on-disk fragment store remains OSV-shaped — only the *yielded*
  records change. Toggling between runs requires no cache wipe.
- The legacy `normalized-cve-data` passthrough is unchanged (already OS-shape).
- Output is uniformly OS-schema: an old grype-db build sees exactly the
  same row shapes the v3 provider produced.

### Mapping rules

| OSV input | OS output |
|---|---|
| `upstream[0]` (`CVE-*`) | `Vulnerability.Name` |
| `severity[type=Ubuntu].score` | `Vulnerability.Severity` (Negligible/Low/Medium/High/Critical, else Unknown) |
| `Ubuntu:22.04:LTS` ecosystem | `NamespaceName: "ubuntu:22.04"` |
| `Ubuntu:Pro:22.04:LTS` (plain ESM) | `NamespaceName: "ubuntu:22.04+esm"` — the `+esm` distro channel (mirrors RHEL EUS's `rhel:X.Y+eus`), carrying the real Pro fix version. Gated by `downconvert_emit_esm`. A plain-Pro slice with no fix emits no `+esm` record (the base wont-fix already discloses it) |
| `Ubuntu:Pro:FIPS*` / Realtime / BlueField | **dropped** — their builds diverge from base, so their fixes can't resolve a base disclosure |
| `ranges[].events[].fixed: "x.y.z"` | `FixedIn.Version: "x.y.z"`, `NoAdvisory: false` |
| no `fixed` + `database_specific.anchore.status == "wont-fix"` | `FixedIn.Version: "None"`, `NoAdvisory: true` |
| no `fixed`, no wont-fix marker | `FixedIn.Version: "None"`, `NoAdvisory: false` |
| `database_specific.anchore.fixes[].date` | `FixedIn.Available: {Date, Kind}` |

Pro-only-fix data still surfaces in OS output: by the time downconversion
runs, the inference pass in `_yield_base_with_inferences` has already
merged the synthesized wont-fix entries into the base ecosystem's
`affected[]` list, so they emerge as `FixedIn{Version="None", NoAdvisory=true}`
rows on the base namespace.

### Trade-offs

- **Provenance is lost.** OSV's `database_specific.anchore.inference` and
  per-status annotations have no representation in the OS schema. The
  resulting OS rows are indistinguishable from those v3 produced from
  cve-tracker — which is the point, but it means downstream cannot tell
  which records came from Pro inference vs. real base entries.
- **Six Canonical statuses collapse to three.** OSV-via-Canonical already
  collapsed `released/needed/active/deferred/pending/ignored` to a single
  `affected` status; downconversion preserves only the wont-fix vs. not
  distinction reconstructed via VEX overlay.
- This is a *compatibility shim*, not a recommended long-term path. New
  consumers should adopt the OSV transformer rather than enable this.
