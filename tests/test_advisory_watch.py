"""Unit and integration tests for tools/advisory_watch.py.

All network responses in this file come from labelled fixtures under
tests/fixtures/ or inline fake transports — no test in this suite ever
touches a live provider, and nothing here executes exploit code.
"""

import json
import os
import re
import sys
import tempfile
import unittest
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path

import datetime as dt

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import advisory_watch as aw  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def http_error(code, reason="boom", headers=None):
    err = urllib.error.HTTPError("url", code, reason, headers or {}, None)
    return err


class RecordingSleeper:
    """Replaces time.sleep so tests can assert pacing without waiting.

    Optionally ticks a companion FakeClock so simulated time advances the
    way real time would while sleeping.
    """

    def __init__(self, clock=None):
        self.calls = []
        self.clock = clock

    def __call__(self, seconds):
        self.calls.append(seconds)
        if self.clock is not None:
            self.clock.t += seconds


class FakeClock:
    """Deterministic monotonic clock for rate-limit assertions."""

    def __init__(self, start=0.0, step=0.0):
        self.t = start
        self.step = step

    def __call__(self):
        self.t += self.step
        return self.t


class RouteTransport:
    """Fake transport: routes URLs to canned responses or exceptions.

    Each route is (predicate, list_of_outcomes). An outcome is a JSON
    value, an Exception instance, or (exception, n_times) to fail n times
    before yielding the next outcome.
    """

    def __init__(self):
        self.routes = []
        self.calls = []

    def add(self, predicate, outcomes):
        self.routes.append((predicate, list(outcomes)))

    def get_bytes(self, url):
        self.calls.append(url)
        for predicate, outcomes in self.routes:
            if predicate(url):
                if not outcomes:
                    raise AssertionError("route exhausted for %s" % url)
                outcome = outcomes.pop(0)
                if isinstance(outcome, tuple) and isinstance(outcome[0], Exception):
                    err, n = outcome
                    if n > 1:
                        outcomes.insert(0, (err, n - 1))
                    raise err
                if isinstance(outcome, Exception):
                    raise outcome
                if isinstance(outcome, (dict, list)):
                    return json.dumps(outcome).encode("utf-8")
                return outcome
        raise AssertionError("no route for %s" % url)


def paced(transport, min_interval=0):
    """Transport with recording sleeper + fake clock (no real sleeps)."""
    clock = FakeClock()
    sleeper = RecordingSleeper(clock=clock)
    return aw.Transport(transport=transport, sleeper=sleeper, clock=clock,
                        min_interval=min_interval)


class TempStateDir:
    """Context manager giving each test an isolated .advisory-watch dir."""

    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "state"
        return self

    def __exit__(self, *exc):
        self._tmp.cleanup()
        return False


class TestNvdFetchPagination(unittest.TestCase):
    """NVD CVE 2.0 listing: offset pagination, page cap, noRejected."""

    def _pages(self, total, per_page, vulns):
        """Build NVD envelope pages of `per_page` items from `vulns`."""
        pages = []
        for start in range(0, total, per_page):
            chunk = vulns[start:start + per_page]
            pages.append({
                "resultsPerPage": len(chunk),
                "startIndex": start,
                "totalResults": total,
                "vulnerabilities": [{"cve": v} for v in chunk],
            })
        return pages

    def _vulns(self, n):
        return [{"id": "CVE-2026-%06d" % i,
                 "published": "2026-11-01T00:00:00.000",
                 "lastModified": "2026-11-02T00:00:00.000",
                 "vulnStatus": "Analyzed",
                 "descriptions": [{"lang": "en", "value": "desc %d" % i}],
                 "references": []} for i in range(n)]

    def _transport(self, t):
        return paced(t)

    def test_pages_through_all_results(self):
        t = RouteTransport()
        t.add(lambda u: "cves/2.0" in u, self._pages(5, 2, self._vulns(5)))
        transport = self._transport(t)
        got = aw.nvd_list(transport, {"lastModStartDate": "2026-11-01T00:00:00.000"})
        self.assertEqual([v["id"] for v in got], ["CVE-2026-%06d" % i for i in range(5)])
        self.assertEqual(len(t.calls), 3)
        self.assertIn("startIndex=0", t.calls[0])
        self.assertIn("startIndex=2", t.calls[1])
        self.assertIn("startIndex=4", t.calls[2])

    def test_page_cap_bounds_the_run(self):
        t = RouteTransport()
        t.add(lambda u: "cves/2.0" in u, self._pages(9, 2, self._vulns(9)))
        transport = self._transport(t)
        got = aw.nvd_list(transport, {}, max_pages=2)
        self.assertEqual(len(got), 4)  # stopped after 2 pages
        self.assertEqual(len(t.calls), 2)

    def test_no_rejected_requested_on_listing(self):
        t = RouteTransport()
        t.add(lambda u: "cves/2.0" in u, self._pages(2, 2000, self._vulns(2)))
        transport = self._transport(t)
        aw.nvd_list(transport, {})
        # bare flag per NVD docs ("provided without a parameter value")
        self.assertIn("noRejected", t.calls[0])
        self.assertNotIn("noRejected=", t.calls[0])

    def test_results_per_page_within_api_maximum(self):
        t = RouteTransport()
        t.add(lambda u: "cves/2.0" in u, self._pages(2, 2000, self._vulns(2)))
        transport = self._transport(t)
        aw.nvd_list(transport, {})
        self.assertRegex(t.calls[0], r"resultsPerPage=(\d+)")
        m = re.search(r"resultsPerPage=(\d+)", t.calls[0])
        self.assertLessEqual(int(m.group(1)), 2000)


class TestRetryBackoff(unittest.TestCase):
    """Retry with exponential backoff; Retry-After honored; fail closed."""

    def test_retries_5xx_then_succeeds(self):
        t = RouteTransport()
        t.add(lambda u: True, [(http_error(503), 2), {"ok": 1}])
        sleeper = RecordingSleeper()
        transport = aw.Transport(transport=t, sleeper=sleeper, min_interval=0)
        got = transport.get_json("https://example.test/x")
        self.assertEqual(got, {"ok": 1})
        self.assertEqual(sleeper.calls, [2, 4])

    def test_gives_up_after_max_retries(self):
        t = RouteTransport()
        t.add(lambda u: True, [(http_error(503), 99)])
        sleeper = RecordingSleeper()
        transport = aw.Transport(transport=t, sleeper=sleeper, min_interval=0)
        with self.assertRaises(aw.FetchError):
            transport.get_json("https://example.test/x")
        self.assertEqual(sleeper.calls, [2, 4, 8])

    def test_retry_after_header_overrides_backoff(self):
        t = RouteTransport()
        err = http_error(429, "rate", {"Retry-After": "10"})
        t.add(lambda u: True, [(err, 1), {"ok": 1}])
        sleeper = RecordingSleeper()
        transport = aw.Transport(transport=t, sleeper=sleeper, min_interval=0)
        self.assertEqual(transport.get_json("https://example.test/x"), {"ok": 1})
        self.assertEqual(sleeper.calls, [10])

    def test_4xx_does_not_retry(self):
        t = RouteTransport()
        t.add(lambda u: True, [http_error(404)])
        sleeper = RecordingSleeper()
        transport = aw.Transport(transport=t, sleeper=sleeper, min_interval=0)
        with self.assertRaises(aw.FetchError):
            transport.get_json("https://example.test/x")
        self.assertEqual(sleeper.calls, [])


class TestRateLimiting(unittest.TestCase):
    """Politeness pacing: >=6s between consecutive NVD requests."""

    def test_nvd_requests_paced(self):
        t = RouteTransport()
        t.add(lambda u: "services.nvd.nist.gov" in u,
              [{"resultsPerPage": 0, "startIndex": 0, "totalResults": 0,
                "vulnerabilities": []}] * 3)
        clock = FakeClock()  # time only advances via the recorded sleeps
        sleeper = RecordingSleeper(clock=clock)
        transport = aw.Transport(transport=t, sleeper=sleeper,
                                 clock=clock, min_interval=6.0)
        transport.get_json("https://services.nvd.nist.gov/rest/json/cves/2.0")
        transport.get_json("https://services.nvd.nist.gov/rest/json/cves/2.0?x=1")
        # the two request starts must be a full 6s apart: first is free,
        # second sleeps the whole interval, third sleeps again
        self.assertEqual(sleeper.calls, [6.0])
        transport.get_json("https://services.nvd.nist.gov/rest/json/cves/2.0?x=2")
        self.assertEqual(sleeper.calls, [6.0, 6.0])


class TestGhCli(unittest.TestCase):
    """GHSA via existing authenticated `gh api` — never stores tokens."""

    def test_paginated_slurp_flattens_pages(self):
        seen = []

        def runner(args):
            seen.append(args)
            # real `gh api --paginate` emits concatenated JSON documents
            return json.dumps([{"ghsa_id": "G1"}]) + "\n" + json.dumps([{"ghsa_id": "G2"}])

        gh = aw.GhCli(runner=runner)
        advisories = gh.paginated("advisories?per_page=100")
        self.assertEqual([a["ghsa_id"] for a in advisories], ["G1", "G2"])
        self.assertIn("--paginate", seen[0])
        self.assertNotIn("--slurp", seen[0])  # older gh CLIs reject --slurp

    def test_paginated_caps_items(self):
        def runner(args):
            # two 100-item pages, concatenated like real gh output
            page = [{"ghsa_id": "G%d" % i} for i in range(100)]
            return json.dumps(page) + "\n" + json.dumps(page)

        gh = aw.GhCli(runner=runner)
        advisories = gh.paginated("advisories?per_page=100", max_items=150)
        self.assertEqual(len(advisories), 150)

    def test_gh_failure_raises_fetch_error(self):
        def runner(args):
            raise RuntimeError("gh: auth required")

        gh = aw.GhCli(runner=runner)
        with self.assertRaises(aw.FetchError):
            gh.paginated("advisories")


# ---------------------------------------------------------------------------
# state, upsert, withdrawal
# ---------------------------------------------------------------------------

def _kev(cve, date_added="2026-11-13", **kw):
    base = {
        "cveID": cve,
        "vendorProject": "V",
        "product": "P",
        "vulnerabilityName": "Vuln",
        "dateAdded": date_added,
        "shortDescription": "d",
        "requiredAction": "patch",
        "dueDate": "2026-11-16",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "",
    }
    base.update(kw)
    return base


def _nvd(cve, published="2026-11-01T00:00:00.000", modified=None,
         severity="HIGH", score=8.8):
    return {
        "id": cve,
        "published": published,
        "lastModified": modified or published,
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "nvd desc"}],
        "metrics": {"cvssMetricV31": [{
            "type": "Primary",
            "cvssData": {"baseScore": score, "baseSeverity": severity,
                         "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        }]},
        "weaknesses": [],
        "references": [],
        "configurations": [],
    }


class TestStateAtomicUpsert(unittest.TestCase):
    """Atomic state persistence and stable upserts keyed on CVE id."""

    def test_state_written_atomically_and_loadable(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.items["CVE-1"] = {"id": "CVE-1", "status": "NEW"}
            st.save()
            on_disk = json.loads((tmp.path / "state.json").read_text())
            self.assertEqual(on_disk["items"]["CVE-1"]["status"], "NEW")
            # atomic write leaves no temp files behind
            leftovers = [p.name for p in tmp.path.iterdir()
                         if p.name != "state.json"]
            self.assertEqual(leftovers, [])

    def test_upsert_new_modified_unchanged(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            events = []
            events.append(st.upsert_kev(_kev("CVE-A")))
            st.save()
            st2 = aw.State(tmp.path)
            events.append(st2.upsert_kev(_kev("CVE-A")))  # identical
            st2.save()
            st3 = aw.State(tmp.path)
            events.append(st3.upsert_kev(_kev("CVE-A",
                                             shortDescription="changed")))
            self.assertEqual(events, ["NEW", "UNCHANGED", "UPDATED"])

    def test_nvd_last_modified_advances_only_on_newer_timestamp(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_nvd(_nvd("CVE-A", modified="2026-11-01T00:00:00.000"))
            st.save()
            st2 = aw.State(tmp.path)
            ev = st2.upsert_nvd(_nvd("CVE-A", modified="2026-11-01T00:00:00.000"))
            self.assertEqual(ev, "UNCHANGED")
            ev = st2.upsert_nvd(_nvd("CVE-A", modified="2026-11-05T00:00:00.000"))
            self.assertEqual(ev, "UPDATED")
            ev = st2.upsert_nvd(_nvd("CVE-A", modified="2026-11-03T00:00:00.000"))
            self.assertEqual(ev, "UNCHANGED")  # older data never regresses

    def test_withdrawn_flips_status_never_deletes(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-A"))
            st.save()
            st2 = aw.State(tmp.path)
            ghsa = {"ghsa_id": "GHSA-x", "cve_id": "CVE-A",
                    "withdrawn_at": "2026-11-14T00:00:00Z"}
            ev = st2.upsert_ghsa(ghsa)
            self.assertEqual(ev, "WITHDRAWN")
            self.assertIn("CVE-A", st2.items)  # still present
            self.assertEqual(st2.items["CVE-A"]["status"], "WITHDRAWN")
            self.assertEqual(st2.items["CVE-A"]["withdrawn_evidence"],
                             ["GHSA-x@2026-11-14T00:00:00Z"])


class TestProviderFailureIsolation(unittest.TestCase):
    """A failed provider must not delete or downgrade existing entries."""

    def test_failed_provider_marks_run_but_keeps_items(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-A"))
            st.save()
            st2 = aw.State(tmp.path)
            st2.record_provider_status("kev", "FAILED", "503 after retries")
            st2.record_provider_status("nvd", "OK", "")
            self.assertEqual(st2.provider_status["kev"]["status"], "FAILED")
            # item untouched by the failure
            self.assertEqual(st2.items["CVE-A"]["status"], "ACTIVELY_EXPLOITED")
            st2.save()
            st3 = aw.State(tmp.path)
            self.assertEqual(st3.provider_status["kev"]["status"], "FAILED")

    def test_kev_disappearance_is_not_deletion(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-A"))
            st.save()
            st2 = aw.State(tmp.path)
            # a fresh catalog WITHOUT CVE-A (e.g. catalog replaced) must
            # not silently remove the record
            st2.apply_kev_catalog({"title": "KEV", "catalogVersion": "x",
                                   "dateReleased": "2026-11-14",
                                   "count": 0, "vulnerabilities": []})
            self.assertIn("CVE-A", st2.items)
            self.assertEqual(st2.items["CVE-A"]["status"], "ACTIVELY_EXPLOITED")


class TestPrioritization(unittest.TestCase):
    """High-impact selection: KEV first, severity desc, deterministic."""

    def test_kev_beats_critical_nvd(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_nvd(_nvd("CVE-BIG", severity="CRITICAL", score=9.9))
            st.upsert_kev(_kev("CVE-KEV"))
            st.upsert_nvd(_nvd("CVE-MED", severity="MEDIUM", score=5.0))
            top = st.promote(limit=2)
            self.assertEqual(top[0]["id"], "CVE-KEV")  # exploited first
            self.assertEqual(top[1]["id"], "CVE-BIG")  # then CVSS desc

    def test_low_severity_not_promoted(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_nvd(_nvd("CVE-LOW", severity="LOW", score=2.1))
            self.assertEqual(st.promote(limit=5), [])

    def test_deterministic_ordering(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            for cve in ("CVE-C", "CVE-A", "CVE-B"):
                st.upsert_nvd(_nvd(cve, score=7.7, severity="HIGH"))
            order1 = [x["id"] for x in st.promote(limit=10)]
            with TempStateDir() as tmp2:
                st2 = aw.State(tmp2.path)
                for cve in ("CVE-B", "CVE-A", "CVE-C"):  # different insertion order
                    st2.upsert_nvd(_nvd(cve, score=7.7, severity="HIGH"))
                order2 = [x["id"] for x in st2.promote(limit=10)]
            self.assertEqual(order1, order2)  # same input -> same output

    def test_promote_respects_limit(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            for i in range(20):
                st.upsert_nvd(_nvd("CVE-2026-%06d" % i, score=8.0))
            self.assertEqual(len(st.promote(limit=10)), 10)


class TestPocGate(unittest.TestCase):
    """PoC status fails closed; manual verification survives runs."""

    def test_poc_link_is_pending_unverified(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-A"))
            st.record_poc_link("CVE-A", {"repo": "o/p", "url": "https://github.com/o/p"})
            self.assertEqual(st.items["CVE-A"]["poc_status"], "PENDING_UNVERIFIED")

    def test_confirmed_working_requires_manual_record(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-A"))
            # gate refuses when evidence is incomplete (no control, no review)
            with self.assertRaises(aw.EvidenceError):
                st.set_poc_confirmed("CVE-A", verification={
                    "reproduction": {"env": "local", "version": "6.0.0"},
                    # missing control + review
                })

    def test_confirmed_working_needs_all_three_legs(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-A"))
            v = {
                "reproduction": {"env": "local recreate", "version": "6.0.0"},
                "control": {"version": "6.2.7.1", "result": "not reproducible"},
                "independent_review": {"reviewer": "reviewer-profile", "date": "2026-11-15"},
            }
            st.set_poc_confirmed("CVE-A", verification=v)
            self.assertEqual(st.items["CVE-A"]["poc_status"], "CONFIRMED_WORKING")

    def test_manual_verification_survives_rerun(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-A"))
            v = {
                "reproduction": {"env": "x", "version": "1"},
                "control": {"version": "2", "result": "no repro"},
                "independent_review": {"reviewer": "r", "date": "2026-11-15"},
            }
            st.set_poc_confirmed("CVE-A", verification=v)
            st.save()
            st2 = aw.State(tmp.path)
            # collector reruns upsert the same record; manual record survives
            st2.upsert_kev(_kev("CVE-A"))
            st2.record_poc_link("CVE-A", {"repo": "o/p", "url": "u"})
            self.assertEqual(st2.items["CVE-A"]["poc_status"], "CONFIRMED_WORKING")
            self.assertEqual(st2.items["CVE-A"]["verification"], v)


class TestGhsaEnrichmentBounded(unittest.TestCase):
    """GHSA enriches only CVEs already under watch — not the whole feed."""

    def test_unwatched_ghsa_not_upserted(self):
        kev = {"title": "KEV", "catalogVersion": "1", "dateReleased": "x",
               "count": 1, "vulnerabilities": [_kev("CVE-A")]}
        t = RouteTransport()
        t.add(lambda u: "cisa.gov" in u, [kev])
        t.add(lambda u: "cves/2.0" in u,
              [{"resultsPerPage": 0, "startIndex": 0, "totalResults": 0,
                "vulnerabilities": []}])

        class FakeGh:
            def paginated(self, endpoint, max_items=None):
                return [
                    {"ghsa_id": "G-1", "cve_id": "CVE-A", "severity": "high",
                     "updated_at": "2026-11-14T00:00:00Z", "withdrawn_at": None},
                    {"ghsa_id": "G-2", "cve_id": "CVE-UNRELATED",
                     "severity": "critical", "updated_at": "2026-11-14T00:00:00Z",
                     "withdrawn_at": None},
                ]

        with TempStateDir() as tmp:
            aw.run(transport=paced(t), gh=FakeGh(), state_dir=tmp.path)
            state = json.loads((tmp.path / "state.json").read_text())
            self.assertIn("CVE-A", state["items"])
            self.assertNotIn("CVE-UNRELATED", state["items"])  # bounded
            self.assertEqual(
                state["items"]["CVE-A"]["ghsa_ids"], ["G-1"])

    def test_identical_ghsa_rerun_is_unchanged(self):
        """GHSA enrichment must be idempotent like the other providers.

        A rerun with identical advisory data reports no events — the
        state must not emit a spurious UPDATED event (and must not
        churn last_change) for records the provider did not modify.
        """
        kev = {"title": "KEV", "catalogVersion": "1", "dateReleased": "x",
               "count": 1, "vulnerabilities": [_kev("CVE-A")]}
        t = RouteTransport()
        t.add(lambda u: "cisa.gov" in u, [kev, kev])
        t.add(lambda u: "cves/2.0" in u,
              [{"resultsPerPage": 0, "startIndex": 0, "totalResults": 0,
                "vulnerabilities": []}] * 2)

        class FakeGh:
            def paginated(self, endpoint, max_items=None):
                return [
                    {"ghsa_id": "G-1", "cve_id": "CVE-A", "severity": "high",
                     "updated_at": "2026-11-14T00:00:00Z", "withdrawn_at": None},
                ]

        with TempStateDir() as tmp:
            run1 = aw.run(transport=paced(t), gh=FakeGh(), state_dir=tmp.path)
            run2 = aw.run(transport=paced(t), gh=FakeGh(), state_dir=tmp.path)
        self.assertEqual(run2["events"], [],
                         "identical GHSA data must not re-emit events")


class TestStateBounded(unittest.TestCase):
    """State stays bounded: transient ring drops, durable records persist."""

    def test_compact_drops_old_transient_nvd_items(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            old = "2026-10-01T00:00:00Z"
            st.upsert_nvd(_nvd("CVE-TRANSIENT"), now=old)      # non-KEV ring
            st.upsert_kev(_kev("CVE-KEV"))                      # durable
            st.upsert_nvd(_nvd("CVE-WD"), now=old)
            st.items["CVE-WD"]["status"] = "WITHDRAWN"         # durable
            v = {"reproduction": {"a": 1}, "control": {"b": 2},
                 "independent_review": {"c": 3}}
            st.upsert_nvd(_nvd("CVE-VERIFIED"), now=old)
            st.set_poc_confirmed("CVE-VERIFIED", verification=v)  # durable
            st.compact(retention_days=3, now="2026-11-14T00:00:00Z")
            self.assertNotIn("CVE-TRANSIENT", st.items)
            self.assertIn("CVE-KEV", st.items)
            self.assertIn("CVE-WD", st.items)
            self.assertIn("CVE-VERIFIED", st.items)

    def test_compact_keeps_recent_ring_items(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_nvd(_nvd("CVE-RECENT"), now="2026-11-13T00:00:00Z")
            st.compact(retention_days=3, now="2026-11-14T00:00:00Z")
            self.assertIn("CVE-RECENT", st.items)

    def test_kev_known_ids_cursor_marks_nvd_records(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.cursors["kev_known_ids"] = ["CVE-A"]
            st.upsert_nvd(_nvd("CVE-A"))
            st.apply_kev_marks()
            self.assertTrue(st.items["CVE-A"]["kev"])
            self.assertEqual(st.items["CVE-A"]["status"], "ACTIVELY_EXPLOITED")
            self.assertIn("kev", [s["provider"] for s in st.items["CVE-A"]["sources"]])


class TestIdempotentRerun(unittest.TestCase):
    """End-to-end over fake providers: identical rerun = no changes."""

    def test_second_run_reports_no_events(self):
        today = dt.date.today().isoformat()
        kev = {"title": "KEV", "catalogVersion": "1", "dateReleased": "x",
               "count": 1, "vulnerabilities": [_kev("CVE-A", date_added=today)]}
        empty_nvd = {"resultsPerPage": 0, "startIndex": 0,
                     "totalResults": 0, "vulnerabilities": []}
        t = RouteTransport()
        t.add(lambda u: "cisa.gov" in u, [kev, kev])
        t.add(lambda u: "cves/2.0" in u, [empty_nvd, empty_nvd])
        with TempStateDir() as tmp:
            run1 = aw.run(transport=paced(t), gh=None, state_dir=tmp.path)
            run2 = aw.run(transport=paced(t), gh=None, state_dir=tmp.path)
        self.assertEqual([e for e in run1["events"]], [("CVE-A", "NEW")])
        self.assertEqual(run2["events"], [])  # byte-stable: nothing changed
        self.assertEqual(run1["kev_version"], "1")
        self.assertEqual(run2["kev_version"], "1")


class TestEvidenceSnapshots(unittest.TestCase):
    """Provider documents snapshotted verbatim with SHA-256, gitignored."""

    def test_kev_catalog_snapshotted_with_hash(self):
        kev = {"title": "KEV", "catalogVersion": "9", "dateReleased": "x",
               "count": 0, "vulnerabilities": []}
        t = RouteTransport()
        t.add(lambda u: "cisa.gov" in u, [kev])
        with TempStateDir() as tmp:
            aw.run(transport=paced(t), gh=None, state_dir=tmp.path)
            ev_dir = tmp.path / "evidence" / "kev"
            files = sorted(p for p in ev_dir.glob("*.json")
                           if not p.name.endswith(".sha256.json"))
            self.assertEqual(len(files), 1)
            snap = json.loads(files[0].read_text())
            self.assertEqual(snap["catalogVersion"], "9")  # verbatim content
            meta = json.loads(files[0].with_suffix(".sha256.json").read_text())
            digest = aw.hashlib.sha256(files[0].read_bytes()).hexdigest()
            self.assertEqual(meta["sha256"], digest)
            self.assertEqual(meta["source"], aw.KEV_URL)

    def test_nvd_record_snapshotted(self):
        rec = _nvd("CVE-A")
        envelope = {"resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
                    "vulnerabilities": [{"cve": rec}]}
        t = RouteTransport()
        t.add(lambda u: "cisa.gov" in u,
              [{"title": "KEV", "catalogVersion": "1", "dateReleased": "x",
                "count": 0, "vulnerabilities": []}])
        t.add(lambda u: "cves/2.0" in u, [envelope])
        with TempStateDir() as tmp:
            aw.run(transport=paced(t), gh=None, state_dir=tmp.path)
            files = sorted(p for p in (tmp.path / "evidence" / "nvd").glob("*.json")
                           if not p.name.endswith(".sha256.json"))
            self.assertEqual(len(files), 1)

    def test_evidence_dir_is_gitignored(self):
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn(".advisory-watch", gitignore)

    def test_state_json_is_local_only_not_committed(self):
        """The whole watch state dir is a local working cache.

        The bounded public record is the Advisory posts themselves;
        state.json (thousands of transient NVD ring items, several MB,
        churning daily) must never enter Git history.  Only the docs
        describe the layout.
        """
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertRegex(gitignore, r"(?m)^\.advisory-watch/?\s*$",
                         "the .advisory-watch/ dir must be gitignored whole")


class TestContentValidity(unittest.TestCase):
    """Advisory post contract: sections, at-a-glance keys, PoC label."""

    POST_KEYS = ["CVE / GHSA IDs", "Affected product", "Affected versions",
                 "Fixed in", "Severity (CVSS)", "CWE", "CISA KEV",
                 "PoC status"]
    REQUIRED_SECTIONS = ["## At a glance", "## Summary", "## Root cause",
                         "## Preconditions", "## Impact", "## Remediation",
                         "## Proof of concept", "## Revision history",
                         "## Sources"]

    def _posts(self):
        return sorted((ROOT / "Advisory").glob("**/_posts/*.md"))

    def test_advisory_posts_exist(self):
        self.assertGreaterEqual(len(self._posts()), 1)

    def test_every_post_has_required_sections_in_order(self):
        for post in self._posts():
            text = post.read_text(encoding="utf-8")
            positions = [text.find(s) for s in self.REQUIRED_SECTIONS]
            self.assertEqual(positions, sorted(positions),
                             "%s sections out of order" % post.name)
            self.assertTrue(all(p >= 0 for p in positions),
                            "%s missing a section" % post.name)

    def test_every_post_has_at_a_glance_keys(self):
        for post in self._posts():
            text = post.read_text(encoding="utf-8")
            for key in self.POST_KEYS:
                self.assertIn(key, text, "%s missing %s" % (post.name, key))

    def test_poc_status_labelled(self):
        for post in self._posts():
            text = post.read_text(encoding="utf-8")
            m = re.search(r"\*\*PoC status: ([A-Za-z /-]+)\*\*", text)
            self.assertIsNotNone(m, "%s missing PoC status" % post.name)
            allowed = {"pending / unverified", "none found",
                       "confirmed working (see verification record)",
                       "not found"}
            status = m.group(1).strip().lower()
            self.assertIn(status, allowed,
                          "%s bad PoC status %r" % (post.name, m.group(1)))
            # a PoC status must never appear in the At-a-glance table only —
            # the prose section carries the labelled block too
            self.assertIn("**PoC status:", text)

    def test_confirmed_working_requires_verification_record(self):
        for post in self._posts():
            text = post.read_text(encoding="utf-8")
            m = re.search(r"\*\*PoC status: confirmed working", text)
            if m:
                self.assertRegex(
                    text,
                    r"Verification record:.*(reproduction|control|independent)",
                    "%s claims Confirmed working without a verification record"
                    % post.name)

    def test_every_post_has_revision_row(self):
        for post in self._posts():
            text = post.read_text(encoding="utf-8")
            self.assertRegex(text, r"\| *2026-\d\d-\d\d *\|",
                             "%s missing dated revision row" % post.name)

    def test_description_front_matter_bounded(self):
        for post in self._posts():
            fm = post.read_text(encoding="utf-8").split("---")[1]
            m = re.search(r"description:\s*[\"']?(.*?)[\"']?\s*$",
                          fm, re.M)
            self.assertTrue(m, "%s missing description" % post.name)
            self.assertLessEqual(len(m.group(1)), 120,
                                "%s description >120 chars" % post.name)

    def test_sources_cite_primary_records(self):
        for post in self._posts():
            text = post.read_text(encoding="utf-8")
            self.assertIn("nvd.nist.gov/vuln/detail/", text,
                          "%s must cite the NVD record" % post.name)
            self.assertRegex(text, r"cisa\.gov/known-exploited-vulnerabilities",
                             "%s (KEV CVE) must cite the KEV catalog" % post.name)


if __name__ == "__main__":
    unittest.main()
