# Advisory watch — daily operation & handoff

## What this is

`tools/advisory_watch.py` is a stdlib-only, deterministic collector that
powers the site's high-impact vulnerability watch:

- **Sources** (all public, no API keys required):
  - **CISA KEV** — one GET of the whole catalog; the authoritative
    *exploited-in-the-wild* signal. Entries added in the last 7 days are
    treated as the day's headline candidates (`ACTIVELY_EXPLOITED`).
  - **NVD CVE API 2.0** — `lastModStartDate` window of the last **3
    days** (`NVD_WINDOW_DAYS = 3`, well inside the API's 120-day cap),
    `noRejected` bare flag (per NVD docs the parameter takes no value),
    `resultsPerPage` ≤ 2000, max 3 pages per run, ≥ 6 s between requests
    (public limit: 5 per rolling 30 s). Only HIGH/CRITICAL records are
    kept.
  - **GitHub advisories** — via the *existing authenticated* `gh api`
    (token stays in `gh`'s own config; this script never reads, stores
    or copies it). Used strictly as enrichment and the `withdrawn_at`
    channel for CVEs **already under watch**, via **per-CVE lookups**
    (`gh api advisories?cve_id=<id>`), NOT the old global
    `--paginate` window query (which GitHub truncates past ~1000 items
    while reporting success — per-CVE lookups are exact for the watched
    id and never silently truncate). Per-CVE lookups are paced
    (1 s between lookups).
  - **OSV** — bounded per-watched-CVE record enrichment and the
    `withdrawn` channel via `osv_get` (`GET /v1/vulns/<cve>`), part of
    the default daily path. A clean 404 (no OSV record for that CVE) is
    a non-event; a lookup error marks the provider `FAILED` and never
    deletes or downgrades existing data.
- **State**: `.advisory-watch/state.json` (local working cache,
  **gitignored** — it carries the transient NVD monitoring ring and
  churns daily; the bounded public record is the Advisory posts
  themselves) written atomically (temp file + `os.replace`).
- **Evidence**: **canonicalized** provider JSON (re-serialized, sorted
  keys) + SHA-256 sidecars under `.advisory-watch/evidence/` —
  **gitignored**, never committed. The SHA-256 is computed over exactly
  the stored bytes, so any published field can be re-verified against
  the stored snapshot. Snapshots are **not** byte-verbatim wire
  responses; the digest is reproducible against the snapshot file, not
  the raw HTTP body.

## Daily operation

```sh
cd <repo>
python3 tools/advisory_watch.py            # human-readable summary
python3 tools/advisory_watch.py --json     # machine summary
python3 -m unittest discover -s tests -v   # full test suite
```

### Exit codes (cron contract)

- **0** — the run completed; at least one provider succeeded (partial
  provider failure is still a successful run: the failed provider is
  marked `FAILED` in `state.json` and existing entries are **never**
  deleted or downgraded).
- **1** — *total failure*: every attempted provider failed with no
  events and no promotable items.
- **2** — the run was **refused** for a safety reason and the state was
  **not** updated: either a concurrent run holds the state lock
  (`run.lock`, fail-fast against lost updates), or the previous
  successful run is more than 3 days old and the fixed 3-day
  NVD/GHSA/OSV windows could not cover the gap (a >3-day collector
  outage would otherwise silently miss modifications and withdrawals —
  the collector refuses loudly instead; pass `--ignore-stale` to accept
  the gap explicitly).

Cron alerting should treat **1 and 2 as failures** (and optionally
alert on any `FAILED` provider status even with exit 0).

After a run, the editor (human or agent) promotes at most the top 10 items
from `promote` into a Markdown post under `Advisory/<sub>/_posts/` by
**fully inspecting the vendor advisory / authoritative record first** —
never from a feed snippet. Posts follow the house template (see the
existing advisory posts): At a glance table, Summary, Root cause,
Preconditions, Impact, Remediation, Proof of concept, Revision history,
Sources.

### Reruns are idempotent

Running the collector twice with unchanged upstream data produces zero
events, no duplicated withdrawal evidence, and one logical event per
record per run (a record seen by both KEV and NVD in the same run emits
one `NEW`, not two) — `TestIdempotentRerun`,
`TestWithdrawalIdempotency`, `TestOsvEnrichment`.

## PoC evidence gate

`PoC status` in any post must be one of `none found`, `pending /
unverified`, or `confirmed working`:

- A discovered public PoC link is **untrusted metadata**: recorded with
  `record_poc_link`, status becomes `PENDING_UNVERIFIED`. Presence proves
  nothing (measured rates of malicious/non-working public PoCs are high).
- `set_poc_confirmed` (the fail-closed gate, `tools/advisory_watch.py`)
  requires ALL THREE legs **with substantively meaningful content** —
  hollow dicts (e.g. `{"env": "mock"}` / `{"x": 0}`) fail closed:
  1. `reproduction` — a real, **non-mock** environment; the exact
     affected **component and version** (matching the advisory's
     affected range); the official/default **config** used; and captured
     **execution evidence** (`command` + observed `result`) from a
     controlled, authorized local fixture;
  2. `control` — the exact **fixed** (or meaningfully different) version
     — never the same version as the reproduction — with a concrete
     observed `result` showing the issue does not reproduce;
  3. `independent_review` — a named **reviewer** and an explicit
     **verdict**.
- The collector itself never executes exploit code and never grants
  `CONFIRMED_WORKING`; manual verification records are preserved verbatim
  across runs (`verification` key on the item).
- Mock, weakened, narrow, or default-blocked setups can never be labelled
  generic "Confirmed working".

## Concurrency, coverage gaps and compaction

- **State lock**: a `run.lock` file (O_CREAT|O_EXCL) makes a concurrent
  run refuse to start (exit 2) instead of interleaving state saves and
  losing updates. `os.replace` keeps individual writes atomic.
- **Coverage gaps**: the collector refuses to run (exit 2) when the last
  successful run is older than the 3-day windows, so a >3-day outage is
  a loud failure, never a silent hole in modification/withdrawal
  coverage. `--ignore-stale` accepts the gap explicitly.
- **Compaction** (`compact`, 3-day transient-ring retention) never drops
  KEV, WITHDRAWN, verified (`verification`) or PoC-linked (`pocs`)
  entries — only stale transient monitoring-ring items.

## Scheduling handoff (do NOT schedule from this task)

The intended production schedule is **01:00 Asia/Kuala_Lumpur daily**,
via Hermes cron (see the Hermes cron docs): the durable form is

```sh
hermes cron create "0 1 * * *" --timezone Asia/Kuala_Lumpur \
  "<watch prompt>" --workdir <repo> --name "daily-vuln-watch"
```

created **paused**, test-fired once (`hermes cron run <id>`), then
resumed. A `--no-agent` script job running just the collector is also
valid. This task intentionally does **not** create the job; the owner
should schedule after reviewing the first published advisory updates.
Cron alerting must treat exit codes 1 and 2 as failures (see
"Exit codes").

## Remaining limits (honest)

- Enrichment (GHSA/OSV) is per-watched-CVE only: a CVE **not yet** under
  watch has no GHSA/OSV channel until KEV or NVD surfaces it. A
  GHSA-only advisory for an unwatched CVE (no NVD/KEV record) can be
  missed — GitHub repo-scoped advisories without a CVE id are invisible
  to this design (as observed for GHSA-mg63-h38w-8p9p).
- NVD listing uses a fixed 3-day lastMod window with max 3 pages; a
  day with more than 3 pages of high-impact modifications would
  truncate (bounded-by-design; the page cap keeps the run bounded).
- Withdrawal "un-withdrawal" (an advisory un-withdrawn upstream) is not
  auto-detected: once WITHDRAWN, the record stays WITHDRAWN until
  manually reviewed — conservative by design.
- Evidence snapshots are canonicalized JSON, not raw wire bytes (see
  above).
- The `run.lock` guard is fail-fast, not queueing: a crashed run can
  leave a stale lock that must be removed manually (the file records
  the PID).
- GHSA per-CVE lookups depend on the local `gh` credential; if `gh` is
  absent or unauthorized the ghsa provider is skipped/failed without
  deleting existing data.

## Licensing & attribution

KEV and NVD data are US-government public-domain-ish feeds (NVD requires
the notice: "This product uses data from the NVD API but is not endorsed
or certified by the NVD."). GitHub Advisory Database is CC-BY 4.0 and
requires attribution — posts cite GHSA IDs and links. The site publishes
only bounded *derived* summaries with links, never verbatim mirrored
records; raw evidence snapshots stay local and uncommitted.
