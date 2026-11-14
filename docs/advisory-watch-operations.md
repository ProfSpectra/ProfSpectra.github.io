# Advisory watch — daily operation & handoff

## What this is

`tools/advisory_watch.py` is a stdlib-only, deterministic collector that
powers the site's high-impact vulnerability watch:

- **Sources** (all public, no API keys required):
  - **CISA KEV** — one GET of the whole catalog; the authoritative
    *exploited-in-the-wild* signal. Entries added in the last 7 days are
    treated as the day's headline candidates (`ACTIVELY EXPLOITED`).
  - **NVD CVE API 2.0** — `lastModStartDate` window of the last 8 days,
    `noRejected` bare flag (per NVD docs the parameter takes no value),
    `resultsPerPage` ≤ 2000, max 3 pages per run, ≥ 6 s between requests
    (public limit: 5 per rolling 30 s). Only HIGH/CRITICAL records are
    kept.
  - **GitHub global advisories** — via the *existing authenticated*
    `gh api --paginate` (token stays in `gh`'s own config; this script
    never reads, stores or copies it). Used strictly as enrichment for
    CVEs already under watch, plus the `withdrawn_at` channel.
  - **OSV** — per-record enrichment/withdrawal via `osv_get` (available
    for future use; not part of the default daily path).
- **State**: `.advisory-watch/state.json` (local working cache,
  **gitignored** — it carries the transient NVD monitoring ring and
  churns daily; the bounded public record is the Advisory posts
  themselves) written atomically (temp file + `os.replace`).
- **Evidence**: verbatim provider JSON + SHA-256 sidecars under
  `.advisory-watch/evidence/` — **gitignored**, never committed, kept so
  any published field can be re-verified against the exact fetched bytes.

## Daily operation

```sh
cd <repo>
python3 tools/advisory_watch.py            # human-readable summary
python3 tools/advisory_watch.py --json     # machine summary
python3 -m unittest discover -s tests -v   # full test suite
```

Exit code is non-zero only when every provider failed *and* nothing was
already collected — a partially failed run (e.g. NVD down, KEV fine)
succeeds, marks that provider `FAILED` in `state.json`, and **never**
deletes or downgrades existing entries.

After a run, the editor (human or agent) promotes at most the top 10 items
from `promote` into a Markdown post under `Advisory/<sub>/_posts/` by
**fully inspecting the vendor advisory / authoritative record first** —
never from a feed snippet. Posts follow the house template (see the
existing advisory posts): At a glance table, Summary, Root cause,
Preconditions, Impact, Remediation, Proof of concept, Revision history,
Sources.

### Reruns are idempotent

Running the collector twice with unchanged upstream data produces zero
events and a byte-identical item set (`TestIdempotentRerun`).

## PoC evidence gate

`PoC status` in any post must be one of `none found`, `pending /
unverified`, or `confirmed working`:

- A discovered public PoC link is **untrusted metadata**: recorded with
  `record_poc_link`, status becomes `PENDING_UNVERIFIED`. Presence proves
  nothing (measured rates of malicious/non-working public PoCs are high).
- `set_poc_confirmed` (the fail-closed gate, `tools.advisory_watch.py`)
  requires ALL THREE legs, else it raises and the status stays unchanged:
  1. `reproduction` — locally recreated *official affected release* with
     realistic defaults;
  2. `control` — matched *fixed* build where the issue does NOT reproduce;
  3. `independent_review` — a second party/profile reviews the evidence.
- The collector itself never executes exploit code and never grants
  `CONFIRMED_WORKING`; manual verification records are preserved verbatim
  across runs (`verification` key on the item).
- Mock, weakened, narrow, or default-blocked setups can never be labelled
  generic "Confirmed working".

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

## Licensing & attribution

KEV and NVD data are US-government public-domain-ish feeds (NVD requires
the notice: "This product uses data from the NVD API but is not endorsed
or certified by the NVD."). GitHub Advisory Database is CC-BY 4.0 and
requires attribution — posts cite GHSA IDs and links. The site publishes
only bounded *derived* summaries with links, never verbatim mirrored
records; raw evidence snapshots stay local and uncommitted.
