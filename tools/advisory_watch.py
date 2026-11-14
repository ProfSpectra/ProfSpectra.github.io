#!/usr/bin/env python3
"""ProfSpectra high-impact advisory watch collector.

Stdlib-only, deterministic daily collector for the ProfSpectra Advisory
watch.  Bounded pulls from CISA KEV, NVD CVE API 2.0 and GitHub global
advisories (via the existing authenticated `gh` CLI — no tokens are read,
stored or copied by this script), with OSV record enrichment.  Produces a
small derived JSON state file plus per-run evidence snapshots; it never
executes exploit code and never publishes anything by itself.

Design rules (see docs/advisory-watch-operations.md):
  * no API keys required; NVD is paced (>=6s between requests) and NVD
    listing queries ask for noRejected=true with resultsPerPage <= 2000;
  * state updates are atomic (write temp + os.replace) and idempotent —
    records are upserted by stable IDs, never silently deleted;
  * a failed provider marks that provider FAILED for the run but leaves
    all previously collected entries untouched;
  * withdrawals (GHSA withdrawn_at / OSV withdrawn) flip records to
    WITHDRAWN — visible, never a silent delete;
  * evidence snapshots (verbatim provider JSON + SHA-256) are stored under
    .advisory-watch/evidence/, which is gitignored — only the bounded
    derived data in .advisory-watch/state.json is committed;
  * "PoC: Confirmed working" requires a manually curated verification
    record (reproduction + matched fixed control + independent review);
    the gate fails closed and the collector never grants it itself.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import tempfile
import urllib.error
import urllib.request
from urllib.parse import quote as urlquote
from pathlib import Path

USER_AGENT = "ProfSpectra-Advisory-Watch/1.0 (profspectra.github.io)"
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_API = "https://api.osv.dev/v1/vulns/"
# NVD public rate limit is 5 requests / rolling 30 s without a key; be
# stricter and simpler: one request every 6 s.
NVD_MIN_INTERVAL_S = 6.0
NVD_RESULTS_PER_PAGE = 2000
NVD_WINDOW_DAYS = 3  # lastMod window (research rec), inside the 120-day cap

WATCH_DIR = ".advisory-watch"
STATE_FILE = "state.json"
EVIDENCE_DIR = "evidence"

SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Deterministic promotion order: KEV (actively exploited) first, then
# severity desc, then CVE id — same input, same output, every run.
PROMOTE_LIMIT = 10


class FetchError(Exception):
    """A provider fetch failed after retries; the run fails closed for it."""


class EvidenceError(Exception):
    """A Confirmed-working claim lacked complete evidence; gate fails closed."""


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------

class Transport:
    """JSON GET transport with retry, exponential backoff and pacing.

    ``transport`` is injectable for tests (an object with
    ``get_bytes(url) -> bytes``).  ``sleeper``/``clock`` are injectable for
    deterministic tests of backoff and rate limiting.
    """

    def __init__(self, transport=None, sleeper=time.sleep, clock=time.monotonic,
                 min_interval=NVD_MIN_INTERVAL_S, max_retries=3, timeout=60):
        self._transport = transport
        self._sleeper = sleeper
        self._clock = clock
        self._min_interval = min_interval
        self._max_retries = max_retries
        self._timeout = timeout
        self._last_request_at = None
        self._host_last = {}  # per-host pacing for non-NVD hosts

    def get_bytes(self, url):
        self._pace(url)
        body, headers = self._get_with_retries(url)
        return body

    def get_json(self, url):
        return json.loads(self.get_bytes(url).decode("utf-8"))

    # -- internals ----------------------------------------------------------

    def _host(self, url):
        m = re.match(r"https?://([^/]+)/", url + "/")
        return m.group(1) if m else url

    def _pace(self, url):
        """Sleep so consecutive requests to the same host are polite.

        NVD gets the documented 6-second spacing (its public limit is
        5 requests / 30 s); other hosts get a light default so the run
        cannot hammer anyone.
        """
        host = self._host(url)
        interval = self._min_interval if "nvd.nist.gov" in host else min(self._min_interval, 1.0)
        last = self._host_last.get(host)
        now = self._clock()
        if last is not None:
            wait = interval - (now - last)
            if wait > 0:
                self._sleeper(wait)
                self._host_last[host] = last + interval
                return
        self._host_last[host] = now

    def _get_with_retries(self, url):
        attempts = self._max_retries + 1
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        last_err = None
        for attempt in range(attempts):
            if attempt:
                self._sleeper(self._backoff_seconds(attempt, last_err))
            try:
                return self._single_get(url, headers)
            except urllib.error.HTTPError as e:
                last_err = e
                if 400 <= e.code < 500 and e.code not in (408, 429):
                    raise FetchError("%s -> HTTP %d (no retry)" % (url, e.code))
            except Exception as e:  # network hiccup, timeout, ...
                last_err = e
        raise FetchError("%s failed after %d attempts: %r"
                         % (url, attempts, last_err))

    def _single_get(self, url, headers):
        if self._transport is not None:
            return self._transport.get_bytes(url), {}
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            return resp.read(), dict(resp.headers)

    @staticmethod
    def _backoff_seconds(attempt, err):
        retry_after = None
        if isinstance(err, urllib.error.HTTPError):
            retry_after = err.headers.get("Retry-After") if err.headers else None
            if retry_after is not None:
                try:
                    return max(float(retry_after), 1.0)
                except ValueError:
                    pass
        return float(2 ** attempt)  # 2s, 4s, 8s ...


# ---------------------------------------------------------------------------
# providers
# ---------------------------------------------------------------------------

def nvd_list(transport, params=None, results_per_page=NVD_RESULTS_PER_PAGE,
             max_pages=None):
    """List NVD CVEs with offset pagination.

    Always adds noRejected=true (rejected records are noise for a watch)
    and keeps resultsPerPage within the API maximum of 2000.  Returns the
    merged list of `cve` records across pages.
    """
    params = dict(params or {})
    # NVD docs: noRejected "is provided without a parameter value" — a
    # bare flag.  Rejected records are noise for a watch, so listing
    # queries always set it.
    params["noRejected"] = None
    if results_per_page > NVD_RESULTS_PER_PAGE:
        raise ValueError("resultsPerPage above NVD API maximum (2000)")
    params["resultsPerPage"] = str(results_per_page)
    # NVD rejects %-encoded colons in the ISO timestamps with a 404, so
    # only the reserved characters are quoted — `:` and `-` stay literal.
    # A None value means a bare flag (no `=value`), e.g. noRejected.
    query = "&".join(
        k if v is None else "%s=%s" % (k, urlquote(str(v), safe=":-"))
        for k, v in sorted(params.items()))
    out = []
    start_index = 0
    pages = 0
    while True:
        url = "%s?%s&startIndex=%d" % (NVD_BASE, query, start_index)
        data = transport.get_json(url)
        vulns = data.get("vulnerabilities", [])
        out.extend(v.get("cve") for v in vulns if v.get("cve"))
        pages += 1
        start_index += int(data.get("resultsPerPage", results_per_page))
        total = int(data.get("totalResults", 0))
        if start_index >= total or not vulns:
            break
        if max_pages is not None and pages >= max_pages:
            break
    return out


def nvd_by_id(transport, cve_id):
    """Fetch a single NVD CVE record (used to fully inspect a candidate)."""
    data = transport.get_json("%s?cveIds=%s" % (NVD_BASE, cve_id))
    vulns = data.get("vulnerabilities", [])
    return vulns[0]["cve"] if vulns else None


def kev_fetch(transport):
    """Fetch the whole CISA KEV catalog — one GET, no pagination."""
    return transport.get_json(KEV_URL)


def osv_get(transport, vuln_id):
    """Fetch one OSV record; returns None on a clean 404 (not found)."""
    try:
        return transport.get_json(OSV_API + urlquote(vuln_id))
    except FetchError as e:
        if "404" in str(e):
            return None
        raise


# ---------------------------------------------------------------------------
# GitHub global advisories via the existing authenticated gh CLI
# ---------------------------------------------------------------------------

class GhCli:
    """GitHub public API access through the already-authenticated `gh`.

    The token never passes through this script: `gh` reads its own config.
    Falls back to `gh api --paginate` only when GH_TOKEN is absent.
    """

    def __init__(self, runner=None, max_items=1000):
        self._runner = runner or self._default_runner
        self._max_items_default = max_items

    @staticmethod
    def _default_runner(args):
        proc = subprocess.run(["gh", "api"] + args, capture_output=True,
                              text=True, timeout=120)
        if proc.returncode != 0:
            raise RuntimeError("gh api failed: %s" % proc.stderr.strip())
        return proc.stdout

    def paginated(self, endpoint, max_items=None):
        """Fetch all pages of `gh api --paginate` for endpoint, flattened.

        gh handles cursor pagination (Link headers) itself.  Depending on
        version, `--paginate` emits either one JSON array of page-arrays
        (with --slurp) or a stream of page objects/arrays; both are
        accepted here.  The total item count is capped so the run stays
        bounded.
        """
        max_items = max_items if max_items is not None else self._max_items_default
        try:
            raw = self._runner(["--paginate", endpoint])
        except Exception as e:
            raise FetchError("gh api %s failed: %r" % (endpoint, e))
        items = self._flatten(raw)
        return items[:max_items]

    @staticmethod
    def _flatten(raw):
        """Parse concatenated `gh api --paginate` output into one list."""
        decoder = json.JSONDecoder()
        text = raw.strip()
        items = []
        idx = 0
        while idx < len(text):
            while idx < len(text) and text[idx] in " \t\r\n":
                idx += 1
            if idx >= len(text):
                break
            obj, end = decoder.raw_decode(text, idx)
            idx = end
            if isinstance(obj, list):
                items.extend(obj)
            elif obj is not None:
                items.append(obj)
        return items


# ---------------------------------------------------------------------------
# state: atomic persistence, stable upserts, promotion, PoC gate
# ---------------------------------------------------------------------------

def _now_iso():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(obj):
    """Deterministic JSON: sorted keys, no incidental whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


class State:
    """Persistent, atomically saved watch state.

    ``items`` are keyed by CVE id.  Upserts are event-returning ("NEW" /
    "UPDATED" / "UNCHANGED" / "WITHDRAWN") and never delete: a record that
    vanishes from a provider feed stays in state with its last known data,
    and a provider failure only sets ``provider_status`` — it can never
    silently remove or downgrade existing entries.
    """

    def __init__(self, state_dir):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / STATE_FILE
        self.items = {}
        self.cursors = {}
        self.provider_status = {}
        self.manual = {}  # cve -> manual verification record (PoC gate)
        if self.path.is_file():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.items = data.get("items", {})
            self.cursors = data.get("cursors", {})
            self.provider_status = data.get("provider_status", {})
            # Manual verification records are preserved verbatim across
            # collector runs — the collector never edits or drops them.
            for cve, item in self.items.items():
                if item.get("verification"):
                    self.manual[cve] = item["verification"]

    def save(self):
        """Atomic write: temp file in the same dir + os.replace."""
        payload = {
            "saved_at": _now_iso(),
            "cursors": self.cursors,
            "provider_status": self.provider_status,
            "items": self.items,
        }
        fd, tmp = tempfile.mkstemp(dir=str(self.dir), prefix=".state-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, indent=2, sort_keys=True))
            os.replace(tmp, self.path)
        except BaseException:
            os.unlink(tmp)
            raise

    # -- provider bookkeeping ------------------------------------------------

    def record_provider_status(self, provider, status, note=""):
        self.provider_status[provider] = {"status": status, "note": note,
                                          "at": _now_iso()}

    def _item(self, cve_id, now=None):
        if cve_id not in self.items:
            self.items[cve_id] = {
                "id": cve_id, "first_seen": now or _now_iso(),
                "status": "MONITORING", "poc_status": "NONE_FOUND",
                "sources": [], "ghsa_ids": [], "kev": False,
                "evidence": [],
            }
        return self.items[cve_id]

    # -- upserts (stable, event-returning, never deleting) -------------------

    def upsert_kev(self, entry, now=None):
        cve = entry["cveID"]
        item = self._item(cve, now)
        record = {
            "dateAdded": entry.get("dateAdded"),
            "vendorProject": entry.get("vendorProject"),
            "product": entry.get("product"),
            "vulnerabilityName": entry.get("vulnerabilityName"),
            "requiredAction": entry.get("requiredAction"),
            "dueDate": entry.get("dueDate"),
            "knownRansomwareCampaignUse": entry.get("knownRansomwareCampaignUse"),
            "shortDescription": entry.get("shortDescription"),
        }
        prev = item.get("kev_record")
        changed = prev != record
        if not item["kev"]:
            item["kev"] = True
            item["status"] = "ACTIVELY_EXPLOITED"
            changed = True
        if prev is None and item["kev"] and item["status"] == "ACTIVELY_EXPLOITED" and not changed:
            changed = True
        if changed:
            item["kev_record"] = record
            item["last_change"] = now or _now_iso()
            self._add_source(item, "kev",
                             "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=%s" % cve)
            event = "NEW" if prev is None and item["status"] == "ACTIVELY_EXPLOITED" and len(item["evidence"]) <= 1 else "UPDATED"
            if prev is None:
                event = "NEW"
            return event
        return "UNCHANGED"

    def _cvss_of(self, nvd_record):
        metrics = nvd_record.get("metrics", {})
        best = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for m in metrics.get(key, []):
                data = m.get("cvssData", {})
                if data.get("baseScore") is not None:
                    best = {
                        "score": data.get("baseScore"),
                        "severity": (data.get("baseSeverity") or "").upper() or None,
                        "vector": data.get("vectorString"),
                    }
                    break
            if best:
                break
        return best

    def upsert_nvd(self, record, now=None):
        cve = record["id"]
        item = self._item(cve, now)
        modified = record.get("lastModified")
        prev_modified = item.get("nvd_last_modified")
        if prev_modified is not None and modified is not None and modified <= prev_modified:
            return "UNCHANGED"  # older data never regresses the record
        cvss = self._cvss_of(record)
        item["nvd_last_modified"] = modified
        item["published"] = record.get("published")
        item["vuln_status"] = record.get("vulnStatus")
        item["description"] = next(
            (d["value"] for d in record.get("descriptions", [])
             if d.get("lang") == "en"), None)
        if cvss:
            item["cvss"] = cvss
        item["cwes"] = sorted({w["value"]
                               for w in record.get("weaknesses", [])
                               for w in (w.get("description") or [])
                               if w.get("value")})
        refs = [r.get("url") for r in record.get("references", []) if r.get("url")]
        if refs:
            item["nvd_references"] = refs
        item["last_change"] = now or _now_iso()
        self._add_source(item, "nvd",
                         "https://nvd.nist.gov/vuln/detail/%s" % cve)
        event = "NEW" if prev_modified is None else "UPDATED"
        if item.get("kev"):
            item["status"] = "ACTIVELY_EXPLOITED"
        elif item.get("status") == "MONITORING":
            item["status"] = "NEW" if prev_modified is None else "UPDATED"
        return event

    def upsert_ghsa(self, adv, now=None):
        cve = adv.get("cve_id")
        if not cve:
            return None
        item = self._item(cve, now)
        withdrawn_at = adv.get("withdrawn_at")
        ids = item.setdefault("ghsa_ids", [])
        if adv["ghsa_id"] not in ids:
            ids.append(adv["ghsa_id"])
        record = {
            "ghsa_id": adv["ghsa_id"],
            "updated_at": adv.get("updated_at"),
            "severity": adv.get("severity"),
            "withdrawn_at": withdrawn_at,
        }
        if adv.get("epss"):
            record["epss"] = adv["epss"]
        prev = item.get("ghsa_record")
        if prev == record and not withdrawn_at:
            # identical advisory data: no change, no event (idempotent
            # rerun — spurious UPDATED events would churn last_change)
            return "UNCHANGED"
        item["ghsa_record"] = record
        item["last_ghsa_update"] = adv.get("updated_at")
        item["ghsa_severity"] = adv.get("severity")
        if adv.get("epss"):
            item["epss"] = adv["epss"]
        self._add_source(item, "ghsa", adv.get("html_url")
                         or "https://github.com/advisories/%s" % adv["ghsa_id"])
        if withdrawn_at:
            item["status"] = "WITHDRAWN"
            item.setdefault("withdrawn_evidence", []).append(
                "%s@%s" % (adv["ghsa_id"], withdrawn_at))
            item["last_change"] = now or _now_iso()
            return "WITHDRAWN"
        item["last_change"] = now or _now_iso()
        return "UPDATED"

    def apply_kev_catalog(self, catalog, now=None):
        """Record catalog metadata + the compact known-id cursor.

        The full 1700+-entry catalog is NOT materialized as items; only
        the recent window (run's `kev_window_days`) becomes items.  The
        known-id list is kept as a cursor so NVD records can still be
        marked KEV (ACTIVELY EXPLOITED) via `apply_kev_marks`.
        """
        self.cursors["kev_catalog_version"] = catalog.get("catalogVersion")
        self.cursors["kev_date_released"] = catalog.get("dateReleased")
        self.cursors["kev_known_ids"] = sorted(
            e["cveID"] for e in catalog.get("vulnerabilities", []))

    def apply_kev_marks(self):
        """Mark any watched NVD items that appear in the KEV id cursor."""
        for cve in self.cursors.get("kev_known_ids", []):
            item = self.items.get(cve)
            if item is not None and not item.get("kev"):
                item["kev"] = True
                item["status"] = "ACTIVELY_EXPLOITED"
                self._add_source(
                    item, "kev",
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=%s" % cve)

    def compact(self, retention_days=3, now=None):
        """Prune the transient NVD monitoring ring; keep durable records.

        Dropped: non-KEV items whose last_change is older than
        `retention_days` and that carry no withdrawal or manual
        verification record.  Kept forever: KEV items (actively
        exploited), WITHDRAWN items (correction history), and items with
        a manual verification record.  This bounds state.json while
        never deleting anything the watch has published or corrected.
        """
        now = dt.datetime.strptime(now or _now_iso(),
                                   "%Y-%m-%dT%H:%M:%SZ")
        cutoff = now - dt.timedelta(days=retention_days)
        for cve in list(self.items):
            item = self.items[cve]
            durable = (item.get("kev")
                       or item.get("status") == "WITHDRAWN"
                       or item.get("verification"))
            if durable:
                continue
            changed = item.get("last_change") or item.get("first_seen")
            try:
                when = dt.datetime.strptime(changed, "%Y-%m-%dT%H:%M:%SZ")
            except (TypeError, ValueError):
                continue  # unparsable timestamp: keep, never guess-drop
            if when < cutoff:
                del self.items[cve]

    # -- promotion (high-impact, deterministic) ------------------------------

    def promote(self, limit=PROMOTE_LIMIT):
        """Select the highest-impact items for a daily entry.

        Order: KEV (actively exploited) first, newest dateAdded first;
        then everything else by severity rank desc, CVSS score desc, CVE
        id asc.  Only records with a real impact signal (KEV or
        HIGH/CRITICAL CVSS) are promoted — the watch is not "every new
        CVE".  Same input always yields the same list.
        """
        kev = sorted(
            (it for it in self.items.values()
             if it.get("kev") and it.get("status") != "WITHDRAWN"),
            key=lambda it: (it.get("kev_record") or {}).get("dateAdded") or "",
            reverse=True,
        )
        rest = sorted(
            (it for it in self.items.values()
             if not it.get("kev") and it.get("status") != "WITHDRAWN"
             and SEVERITY_RANK.get(
                 ((it.get("cvss") or {}).get("severity") or "").upper(), 0)
             >= SEVERITY_RANK["HIGH"]),
            key=lambda it: (-SEVERITY_RANK.get(
                ((it.get("cvss") or {}).get("severity") or "").upper(), 0),
                -((it.get("cvss") or {}).get("score") or 0.0),
                it["id"]),
        )
        return (kev + rest)[:limit]

    # -- PoC gate -------------------------------------------------------------

    def record_poc_link(self, cve_id, poc, now=None):
        """Record an untrusted public PoC link; status is PENDING_UNVERIFIED."""
        item = self._item(cve_id, now)
        pocs = item.setdefault("pocs", [])
        if poc not in pocs:
            pocs.append(poc)
        if item.get("poc_status") in (None, "NONE_FOUND"):
            item["poc_status"] = "PENDING_UNVERIFIED"

    def set_poc_confirmed(self, cve_id, verification, now=None):
        """Fail-closed gate for 'PoC: Confirmed working'.

        Requires all three legs: (a) reproduction on the stated affected
        version, (b) a matched fixed control where the issue does NOT
        reproduce, (c) independent review.  Anything less raises
        EvidenceError and the status stays PENDING_UNVERIFIED.  The
        collector itself never calls this — it is for manual verification
        records only.
        """
        legs = ("reproduction", "control", "independent_review")
        for leg in legs:
            if not isinstance(verification.get(leg), dict) or not verification[leg]:
                raise EvidenceError(
                    "Confirmed working requires %r evidence; gate fails closed"
                    % leg)
        item = self._item(cve_id, now)
        item["poc_status"] = "CONFIRMED_WORKING"
        item["verification"] = verification  # preserved verbatim
        item["last_change"] = now or _now_iso()

    # -- internals -------------------------------------------------------------

    def _add_source(self, item, provider, url):
        src = {"provider": provider, "url": url}
        if src not in item["sources"]:
            item["sources"].append(src)


def _snapshot(state_dir, provider, doc_id, payload_obj, source_url, now=None):
    """Store a verbatim provider document + SHA-256 sidecar.

    Evidence lives under <state_dir>/evidence/<provider>/ and is
    gitignored; only the bounded derived state is committed.  Returns the
    snapshot record for state['evidence'].
    """
    ev_dir = Path(state_dir) / EVIDENCE_DIR / provider
    ev_dir.mkdir(parents=True, exist_ok=True)
    stamp = (now or _now_iso()).replace(":", "").replace("-", "")[:14]
    path = ev_dir / ("%s-%s.json" % (doc_id, stamp))
    body = json.dumps(payload_obj, indent=2, sort_keys=True).encode("utf-8")
    path.write_bytes(body)
    digest = hashlib.sha256(body).hexdigest()
    meta = {"sha256": digest, "source": source_url, "fetched_at": now or _now_iso(),
            "bytes": len(body)}
    path.with_suffix(".sha256.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
    return {"provider": provider, "id": doc_id, "path": str(path),
            "sha256": digest, "source": source_url,
            "fetched_at": now or _now_iso()}


# ---------------------------------------------------------------------------
# run orchestration
# ---------------------------------------------------------------------------

def run(transport=None, gh=None, state_dir=WATCH_DIR, repo_root=None,
        kev_window_days=7, now=None):
    """One bounded collection run.  Returns a summary dict.

    Providers run independently: a failed provider sets its status to
    FAILED and the run continues with the others; existing state entries
    are never removed or downgraded because of a provider failure.
    """
    state_dir = Path(state_dir)
    state = State(state_dir)
    transport = transport or Transport()
    events = []
    summary = {
        "at": now or _now_iso(),
        "events": events,
        "providers": {},
        "kev_version": None,
    }

    # CISA KEV — authoritative exploited-in-the-wild signal, single GET
    try:
        catalog = kev_fetch(transport)
        summary["kev_version"] = catalog.get("catalogVersion")
        snap = _snapshot(state_dir, "kev",
                         "catalog-%s" % catalog.get("catalogVersion", "x"),
                         catalog, KEV_URL, now=now)
        state.cursors["kev_snapshot"] = snap["sha256"]
        state.apply_kev_catalog(catalog, now=now)
        cutoff = dt.date.today() - dt.timedelta(days=kev_window_days)
        recent = [e for e in catalog.get("vulnerabilities", [])
                  if dt.datetime.strptime(e["dateAdded"], "%Y-%m-%d").date() >= cutoff]
        state.cursors["kev_recent_events"] = sorted(
            (e["cveID"], e["dateAdded"]) for e in recent)
        # Only the recent window becomes items; the rest of the catalog is
        # the compact kev_known_ids cursor.  Absence from the catalog is
        # never a deletion signal for an existing item.
        for entry in recent:
            ev = state.upsert_kev(entry, now=now)
            if ev and ev != "UNCHANGED":
                events.append((entry["cveID"], ev))
        state.record_provider_status("kev", "OK")
        summary["providers"]["kev"] = "OK"
    except FetchError as e:
        state.record_provider_status("kev", "FAILED", str(e))
        summary["providers"]["kev"] = "FAILED"

    # NVD — recently modified CVEs, high-impact filter
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=NVD_WINDOW_DAYS)
    try:
        params = {
            "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
        }
        records = nvd_list(transport, params, max_pages=3)
        for rec in records:
            if _is_high_impact(rec):
                _snapshot(state_dir, "nvd", rec["id"], rec,
                          "https://nvd.nist.gov/vuln/detail/%s" % rec["id"],
                          now=now)
                ev = state.upsert_nvd(rec, now=now)
                if ev and ev != "UNCHANGED":
                    events.append((rec["id"], ev))
        state.apply_kev_marks()  # KEV ids from the cursor mark NVD items
        state.record_provider_status("nvd", "OK")
        summary["providers"]["nvd"] = "OK"
    except (FetchError, ValueError) as e:
        state.record_provider_status("nvd", "FAILED", str(e))
        summary["providers"]["nvd"] = "FAILED"

    # GitHub global advisories — enrichment + withdrawal channel.  Bounded:
    # only advisories for CVEs already under watch are considered, so the
    # GHSA stream enriches the KEV/NVD candidates instead of importing the
    # whole feed.
    if gh is not None:
        try:
            advisories = gh.paginated(
                "advisories?updated=>%s&per_page=100"
                % since.strftime("%Y-%m-%dT%H:%M:%SZ"))
            watched = set(state.items)
            for adv in advisories:
                if adv.get("cve_id") in watched:
                    ev = state.upsert_ghsa(adv, now=now)
                    if ev and ev != "UNCHANGED":
                        events.append((adv["cve_id"], ev))
            state.record_provider_status("ghsa", "OK")
            summary["providers"]["ghsa"] = "OK"
        except FetchError as e:
            state.record_provider_status("ghsa", "FAILED", str(e))
            summary["providers"]["ghsa"] = "FAILED"

    # GHSA enrichment may have marked items; compact the transient NVD
    # ring so state.json stays bounded.  Durable records (KEV, WITHDRAWN,
    # manual verification) are never dropped.
    state.compact()
    state.save()
    summary["promoted"] = state.promote()
    return summary


def _is_high_impact(nvd_record):
    """NVD records worth watching: KEV-style or HIGH/CRITICAL CVSS."""
    metrics = nvd_record.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            sev = ((m.get("cvssData", {}).get("baseSeverity") or "")
                   .upper())
            if sev:
                return SEVERITY_RANK.get(sev, 0) >= SEVERITY_RANK["HIGH"]
    return False


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv=None):
    """CLI: `python3 tools/advisory_watch.py [--state-dir DIR] [--json]`."""
    ap = argparse.ArgumentParser(description="ProfSpectra advisory watch collector")
    ap.add_argument("--state-dir", default=WATCH_DIR,
                    help="state directory (default: %s)" % WATCH_DIR)
    ap.add_argument("--json", action="store_true",
                    help="emit the run summary as JSON")
    args = ap.parse_args(argv)

    gh = GhCli() if _gh_available() else None
    summary = run(state_dir=args.state_dir, gh=gh)

    if args.json:
        print(json.dumps(summary, indent=2, default=str))
    else:
        print("advisory watch run at %s" % summary["at"])
        for provider, status in sorted(summary["providers"].items()):
            print("  provider %-5s %s" % (provider, status))
        for cve, ev in summary["events"]:
            print("  %-16s %s" % (cve, ev))
        print("  promoted: %s" % ", ".join(i["id"] for i in summary["promoted"]))
    failed = [p for p, s in summary["providers"].items() if s == "FAILED"]
    return 1 if failed and not summary["events"] and not summary["promoted"] else 0


def _gh_available():
    from shutil import which
    return which("gh") is not None


if __name__ == "__main__":
    sys.exit(main())
