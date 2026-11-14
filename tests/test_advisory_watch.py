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

    def test_per_cve_returns_exact_advisories(self):
        seen = []

        def runner(args):
            seen.append(args)
            return json.dumps([
                {"ghsa_id": "G-1", "cve_id": "CVE-A", "withdrawn_at": None}])

        gh = aw.GhCli(runner=runner)
        advisories, raw = gh.per_cve("CVE-A")
        self.assertEqual([a["ghsa_id"] for a in advisories], ["G-1"])
        self.assertEqual(
            raw, json.dumps([
                {"ghsa_id": "G-1", "cve_id": "CVE-A",
                 "withdrawn_at": None}]).encode("utf-8"))
        self.assertEqual(seen[0], ["advisories?cve_id=CVE-A"])
        self.assertNotIn("--paginate", seen[0][0])  # exact per-CVE lookup

    def test_per_cve_wraps_single_object(self):
        def runner(args):
            return json.dumps({"ghsa_id": "G-1", "cve_id": "CVE-A"})

        gh = aw.GhCli(runner=runner)
        advisories, _raw = gh.per_cve("CVE-A")
        self.assertEqual(len(advisories), 1)
        self.assertEqual(advisories[0]["ghsa_id"], "G-1")

    def test_gh_failure_raises_fetch_error(self):
        def runner(args):
            raise RuntimeError("gh: auth required")

        gh = aw.GhCli(runner=runner)
        with self.assertRaises(aw.FetchError):
            gh.per_cve("CVE-A")


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
                "reproduction": {
                    "env": "local authorized fixture (official release "
                           "6.0.0 tarball, default config)",
                    "component": "vulnserver",
                    "version": "6.0.0",
                    "affected_version": "6.0.0",
                    "config": "official defaults (default.xml as shipped)",
                    "command": "python tools/repro.py --target cve-a "
                               "--component vulnserver --version 6.0.0",
                    "result": "issue reproduced: control channel executes "
                              "the documented PoC sequence",
                },
                "control": {
                    "version": "6.2.7.1",
                    "result": "not reproducible on the fixed build "
                              "(same command, exit 0, no effect)",
                },
                "independent_review": {
                    "reviewer": "reviewer-profile",
                    "verdict": "confirmed: reproduction and fixed control "
                               "both sound",
                    "date": "2026-11-15",
                },
            }
            st.set_poc_confirmed("CVE-A", verification=v)
            self.assertEqual(st.items["CVE-A"]["poc_status"], "CONFIRMED_WORKING")

    def test_manual_verification_survives_rerun(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-A"))
            v = {
                "reproduction": {
                    "env": "local authorized fixture (official release "
                           "6.0.0 tarball, default config)",
                    "component": "vulnserver",
                    "version": "6.0.0",
                    "affected_version": "6.0.0",
                    "config": "official defaults",
                    "command": "python tools/repro.py --target cve-a",
                    "result": "issue reproduced",
                },
                "control": {
                    "version": "6.2.7.1",
                    "result": "not reproducible",
                },
                "independent_review": {
                    "reviewer": "r",
                    "verdict": "confirmed",
                    "date": "2026-11-15",
                },
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
    """GHSA enriches only CVEs already under watch — per-CVE lookups."""

    def _kev_catalog(self, today=None):
        today = today or dt.date.today().isoformat()
        return {"title": "KEV", "catalogVersion": "1", "dateReleased": "x",
                "count": 1, "vulnerabilities": [_kev("CVE-A", date_added=today)]}

    def _run(self, tmp, gh, kev=None, nvd_pages=None):
        kev = kev if kev is not None else self._kev_catalog()
        empty_nvd = {"resultsPerPage": 0, "startIndex": 0,
                     "totalResults": 0, "vulnerabilities": []}
        t = RouteTransport()
        t.add(lambda u: "cisa.gov" in u, [kev, kev])
        t.add(lambda u: "cves/2.0" in u, nvd_pages or [empty_nvd, empty_nvd])
        t.add(lambda u: "api.osv.dev" in u, [{}, {}])  # clean 404 -> None
        return aw.run(transport=paced(t), gh=gh, state_dir=tmp.path,
                      enrich_min_interval=0)

    def test_ghsa_lookup_only_for_watched_items(self):
        """Per-CVE lookups: only watched CVEs are queried and upserted."""

        class FakeGh:
            def __init__(self):
                self.asked = []

            def per_cve(self, cve_id):
                self.asked.append(cve_id)
                if cve_id == "CVE-A":
                    adv = [{"ghsa_id": "G-1", "cve_id": "CVE-A",
                            "severity": "high",
                            "updated_at": "2026-11-14T00:00:00Z",
                            "withdrawn_at": None}]
                    return adv, json.dumps(adv).encode("utf-8")
                return [], b"[]"

        gh = FakeGh()
        with TempStateDir() as tmp:
            self._run(tmp, gh)
            state = json.loads((tmp.path / "state.json").read_text())
            self.assertIn("CVE-A", state["items"])
            self.assertEqual(gh.asked, ["CVE-A"])  # only the watched CVE
            self.assertEqual(state["items"]["CVE-A"]["ghsa_ids"], ["G-1"])

    def test_ghsa_failure_does_not_delete_existing_data(self):
        """A failed per-CVE GHSA lookup marks the provider FAILED but
        never deletes or downgrades existing entries."""

        class FailingGh:
            def per_cve(self, cve_id):
                raise aw.FetchError("gh api failed: auth required")

        with TempStateDir() as tmp:
            run1 = self._run(tmp, FakeGh_ok())  # seed G-1 on CVE-A
            with TempStateDir() as tmp2:  # fresh: prove old data survives
                pass
            run2 = self._run(tmp, FailingGh())
            state = json.loads((tmp.path / "state.json").read_text())
            self.assertTrue(str(run2["providers"]["ghsa"]).startswith("FAILED"))
            self.assertEqual(state["items"]["CVE-A"]["ghsa_ids"], ["G-1"])
            self.assertEqual(state["provider_status"]["ghsa"]["status"],
                             "FAILED")

    def test_ghsa_withdrawal_beyond_window_is_found_per_cve(self):
        """Regression (review finding 2): the old global window query
        silently truncated at 1000 items — a watched item past the cap
        was missed.  Per-CVE lookup must find a withdrawal regardless of
        where it sits in the global feed."""

        class FakeGh:
            def per_cve(self, cve_id):
                if cve_id == "CVE-A":
                    adv = [{"ghsa_id": "G-1", "cve_id": "CVE-A",
                            "severity": "high",
                            "updated_at": "2026-11-14T00:00:00Z",
                            "withdrawn_at": "2026-11-14T00:00:00Z"}]
                    return adv, json.dumps(adv).encode("utf-8")
                return [], b"[]"

        with TempStateDir() as tmp:
            run1 = self._run(tmp, FakeGh())
            events = [e for e in run1["events"]]
            self.assertIn(("CVE-A", "WITHDRAWN"), events)
            state = json.loads((tmp.path / "state.json").read_text())
            self.assertEqual(state["items"]["CVE-A"]["status"], "WITHDRAWN")

    def test_identical_ghsa_rerun_is_unchanged(self):
        """GHSA enrichment must be idempotent like the other providers.

        A rerun with identical advisory data reports no events — the
        state must not emit a spurious UPDATED event (and must not
        churn last_change) for records the provider did not modify.
        """

        class FakeGh:
            def per_cve(self, cve_id):
                if cve_id == "CVE-A":
                    adv = [{"ghsa_id": "G-1", "cve_id": "CVE-A",
                            "severity": "high",
                            "updated_at": "2026-11-14T00:00:00Z",
                            "withdrawn_at": None}]
                    return adv, json.dumps(adv).encode("utf-8")
                return [], b"[]"

        with TempStateDir() as tmp:
            run1 = self._run(tmp, FakeGh())
            run2 = self._run(tmp, FakeGh())
        self.assertEqual(run2["events"], [],
                         "identical GHSA data must not re-emit events")


class FakeGh_ok:
    def per_cve(self, cve_id):
        if cve_id == "CVE-A":
            adv = [{"ghsa_id": "G-1", "cve_id": "CVE-A", "severity": "high",
                    "updated_at": "2026-11-14T00:00:00Z",
                    "withdrawn_at": None}]
            return adv, json.dumps(adv).encode("utf-8")
        return [], b"[]"


class TestWithdrawalIdempotency(unittest.TestCase):
    """Regression tests for the review findings (defender t_df5e3b1b).

    Each test reproduces a probe from the independent review:
    P1 (withdrawal rerun non-idempotent), P2 (stale NEW status),
    P5 (hollow PoC gate legs), plus the OSV dead-code and GHSA
    truncation findings.
    """

    def test_identical_withdrawn_rerun_is_unchanged(self):
        """P1: an unchanged already-withdrawn record yields no new event
        and no duplicated withdrawn evidence on rerun."""
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-A"))
            adv = {"ghsa_id": "G-x", "cve_id": "CVE-A",
                   "updated_at": "2026-11-14T00:00:00Z",
                   "withdrawn_at": "2026-11-14T00:00:00Z", "severity": "high"}
            ev1 = st.upsert_ghsa(dict(adv))
            ev2 = st.upsert_ghsa(dict(adv))  # identical rerun
            ev3 = st.upsert_ghsa(dict(adv))
            item = st.items["CVE-A"]
            self.assertEqual(ev1, "WITHDRAWN")
            self.assertEqual(ev2, "UNCHANGED",
                             "identical withdrawn rerun must be UNCHANGED")
            self.assertEqual(ev3, "UNCHANGED")
            self.assertEqual(item.get("withdrawn_evidence"),
                             ["G-x@2026-11-14T00:00:00Z"],
                             "withdrawn_evidence must not be duplicated")

    def test_modified_item_cannot_remain_status_new(self):
        """P2: an NVD-modified item transitions truthfully — status NEW
        only until the first change, UPDATED after."""
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_nvd(_nvd("CVE-B", modified="2026-11-01T00:00:00.000"))
            self.assertEqual(st.items["CVE-B"]["status"], "NEW")
            ev = st.upsert_nvd(_nvd("CVE-B", modified="2026-11-05T00:00:00.000"))
            status = st.items["CVE-B"]["status"]
            self.assertEqual(ev, "UPDATED")
            self.assertEqual(status, "UPDATED",
                             "a modified item must not remain status NEW")

    def test_kev_withdrawn_state_survives_nvd_update(self):
        """KEV/withdrawn states are never broken by the transition fix."""
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-A"))
            st.upsert_nvd(_nvd("CVE-A", modified="2026-11-01T00:00:00.000"))
            self.assertEqual(st.items["CVE-A"]["status"], "ACTIVELY_EXPLOITED")
            st.upsert_ghsa({"ghsa_id": "G-x", "cve_id": "CVE-A",
                           "updated_at": "2026-11-14T00:00:00Z",
                           "withdrawn_at": "2026-11-14T00:00:00Z"})
            self.assertEqual(st.items["CVE-A"]["status"], "WITHDRAWN")
            # a later NVD modification must not silently un-withdraw
            st.upsert_nvd(_nvd("CVE-A", modified="2026-11-20T00:00:00.000"))
            self.assertEqual(st.items["CVE-A"]["status"], "WITHDRAWN")

    def test_one_logical_event_per_record_per_run(self):
        """Live probe: CVE-2026-114713 got events [NEW, NEW] in one run
        (KEV upsert + NVD upsert of the same record).  One logical event
        per record per run: the second NEW is suppressed."""
        today = dt.date.today().isoformat()
        kev = {"title": "KEV", "catalogVersion": "1", "dateReleased": "x",
               "count": 1, "vulnerabilities": [_kev("CVE-A", date_added=today)]}
        rec = _nvd("CVE-A", modified=today + "T00:00:00.000")
        envelope = {"resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
                    "vulnerabilities": [{"cve": rec}]}
        t = RouteTransport()
        t.add(lambda u: "cisa.gov" in u, [kev])
        t.add(lambda u: "cves/2.0" in u, [envelope])
        t.add(lambda u: "api.osv.dev" in u, [{}])  # clean 404 -> None
        with TempStateDir() as tmp:
            run1 = aw.run(transport=paced(t), gh=None, state_dir=tmp.path,
                          enrich_min_interval=0)
        news = [e for e in run1["events"] if e[1] == "NEW"]
        self.assertEqual(news, [("CVE-A", "NEW")],
                         "one NEW per record per run, not one per provider")

    def test_poc_gate_rejects_hollow_legs(self):
        """P5: semantically empty legs (mock env, control={x:0}, review
        ={y:0}) must fail closed, not pass on mere presence."""
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-C"))
            with self.assertRaises(aw.EvidenceError):
                st.set_poc_confirmed("CVE-C", {
                    "reproduction": {"env": "mock"},
                    "control": {"x": 0},
                    "independent_review": {"y": 0}})
            # gate refused before mutating: status is whatever it was
            # before the failed attempt (no CONFIRMED_WORKING grant)
            self.assertNotEqual(st.items["CVE-C"]["poc_status"],
                                "CONFIRMED_WORKING")

    def test_poc_gate_rejects_same_version_control(self):
        """A control on the same version as the reproduction proves
        nothing and must fail closed."""
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-C"))
            with self.assertRaises(aw.EvidenceError):
                st.set_poc_confirmed("CVE-C", {
                    "reproduction": {"env": "local fixture", "component": "c",
                                    "version": "6.0.0",
                                    "affected_version": "6.0.0",
                                    "config": "defaults",
                                    "command": "cmd", "result": "repro"},
                    "control": {"version": "6.0.0", "result": "no repro"},
                    "independent_review": {"reviewer": "r",
                                            "verdict": "confirmed"}})

    def test_poc_gate_requires_review_date(self):
        """The card's PoC gate legs: reviewer/date/verdict — an
        independent review without a date is not attributable evidence
        and must fail closed."""
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-C"))
            with self.assertRaises(aw.EvidenceError):
                st.set_poc_confirmed("CVE-C", {
                    "reproduction": {
                        "env": "local authorized fixture",
                        "component": "c", "version": "6.0.0",
                        "affected_version": "6.0.0",
                        "config": "official defaults",
                        "command": "cmd", "result": "repro"},
                    "control": {"version": "6.2.0", "result": "no repro"},
                    "independent_review": {"reviewer": "r",
                                            "verdict": "confirmed"
                                            # date missing
                                            }})
            # gate refused before mutating
            self.assertNotEqual(st.items["CVE-C"]["poc_status"],
                                "CONFIRMED_WORKING")

    def test_run_lock_refuses_concurrent_runs(self):
        """R2: a concurrent run refuses to start instead of interleaving
        state saves (lost updates)."""
        with TempStateDir() as tmp:
            kev = {"title": "KEV", "catalogVersion": "1", "dateReleased": "x",
                   "count": 0, "vulnerabilities": []}
            t = RouteTransport()
            t.add(lambda u: "cisa.gov" in u, [kev])
            lock = tmp.path / "run.lock"
            lock.parent.mkdir(parents=True, exist_ok=True)
            lock.write_text("123\n")
            with self.assertRaises(RuntimeError):
                aw.run(transport=paced(t), gh=None, state_dir=tmp.path)
            # the refused run must not have removed the incumbent lock
            self.assertTrue(lock.exists())

    def test_stale_coverage_gap_fails_loudly(self):
        """R3: a previous run older than MAX_COVERAGE_GAP_DAYS makes the
        run refuse loudly (the fixed 3-day windows cannot cover the
        gap) instead of silently missing modifications/withdrawals."""
        with TempStateDir() as tmp:
            stale = "2026-10-01T00:00:00Z"
            payload = {"saved_at": stale, "cursors": {"last_run_at": stale},
                       "provider_status": {}, "items": {}}
            tmp.path.mkdir(parents=True, exist_ok=True)
            (tmp.path / "state.json").write_text(json.dumps(payload))
            kev = {"title": "KEV", "catalogVersion": "1", "dateReleased": "x",
                   "count": 0, "vulnerabilities": []}
            t = RouteTransport()
            t.add(lambda u: "cisa.gov" in u, [kev])
            with self.assertRaises(RuntimeError):
                aw.run(transport=paced(t), gh=None, state_dir=tmp.path)
            # ignore_stale accepts the gap explicitly
            aw.run(transport=paced(t), gh=None, state_dir=tmp.path,
                   ignore_stale=True, enrich_min_interval=0)

    def test_stale_nvd_coverage_refuses_even_with_recent_runs(self):
        """R3 hole: the collector ran yesterday (last_run_at fresh) but
        NVD has not SUCCEEDED for >3 days (daily failures).  The next
        run's 3-day window cannot cover the missed modifications — it
        must refuse loudly, not silently start a fresh window."""

        def _run_and_read(tmp, kev_ok=True, nvd_ok=True):
            class T:
                def get_bytes(self, url):
                    if "cisa.gov" in url:
                        if not kev_ok:
                            raise aw.FetchError("kev down")
                        return json.dumps({
                            "title": "KEV", "catalogVersion": "1",
                            "dateReleased": "x", "count": 0,
                            "vulnerabilities": []}).encode()
                    if "cves/2.0" in url:
                        if not nvd_ok:
                            raise aw.FetchError("nvd down")
                        return json.dumps({
                            "resultsPerPage": 0, "startIndex": 0,
                            "totalResults": 0,
                            "vulnerabilities": []}).encode()
                    raise aw.FetchError("osv down")

            transport = aw.Transport(transport=T(), sleeper=lambda s: None,
                                     clock=lambda: 0.0, min_interval=0)
            return aw.run(transport=transport, gh=None, state_dir=tmp.path,
                          enrich_min_interval=0)

        with TempStateDir() as tmp:
            fresh = dt.datetime.now(dt.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
            old = "2026-10-01T00:00:00Z"
            payload = {"saved_at": fresh,
                       "cursors": {"last_run_at": fresh,
                                   "nvd_last_ok": old},
                       "provider_status": {}, "items": {}}
            tmp.path.mkdir(parents=True, exist_ok=True)
            (tmp.path / "state.json").write_text(json.dumps(payload))
            with self.assertRaises(RuntimeError):
                _run_and_read(tmp)
            # explicit acceptance still runs and refreshes the cursor
            summary = None
            class T2:
                def get_bytes(self, url):
                    if "cisa.gov" in url:
                        return json.dumps({
                            "title": "KEV", "catalogVersion": "1",
                            "dateReleased": "x", "count": 0,
                            "vulnerabilities": []}).encode()
                    return json.dumps({
                        "resultsPerPage": 0, "startIndex": 0,
                        "totalResults": 0,
                        "vulnerabilities": []}).encode()
            transport = aw.Transport(transport=T2(), sleeper=lambda s: None,
                                     clock=lambda: 0.0, min_interval=0)
            summary = aw.run(transport=transport, gh=None,
                             state_dir=tmp.path, ignore_stale=True,
                             enrich_min_interval=0)
            state = json.loads((tmp.path / "state.json").read_text())
            self.assertEqual(summary["providers"]["nvd"], "OK")
            self.assertEqual(state["cursors"]["nvd_last_ok"], summary["at"])

    def test_failed_nvd_day_does_not_advance_coverage_cursor(self):
        """R3 hole: a run where NVD failed must not advance the NVD
        coverage cursor — otherwise the next run starts a fresh 3-day
        window and silently misses the failed day's modifications."""

        class KevOkNvdFail:
            def get_bytes(self, url):
                if "cisa.gov" in url:
                    return json.dumps({
                        "title": "KEV", "catalogVersion": "1",
                        "dateReleased": "x", "count": 0,
                        "vulnerabilities": []}).encode()
                raise aw.FetchError("nvd down")

        with TempStateDir() as tmp:
            transport = aw.Transport(transport=KevOkNvdFail(),
                                     sleeper=lambda s: None,
                                     clock=lambda: 0.0, min_interval=0)
            aw.run(transport=transport, gh=None, state_dir=tmp.path,
                   enrich_min_interval=0)
            state = json.loads((tmp.path / "state.json").read_text())
            self.assertIsNone(state["cursors"].get("nvd_last_ok"),
                              "a failed NVD day must not advance the "
                              "coverage cursor")

    def test_compact_never_drops_poc_linked_entries(self):
        """R4: transient items carrying PoC links are never dropped by
        compaction — they are pending verification evidence."""
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            old = "2026-10-01T00:00:00Z"
            st.upsert_nvd(_nvd("CVE-POC"), now=old)
            st.record_poc_link("CVE-POC", {"repo": "o/p", "url": "u"})
            st.compact(retention_days=3, now="2026-11-14T00:00:00Z")
            self.assertIn("CVE-POC", st.items,
                          "PoC-linked items must survive compaction")


class TestOsvEnrichment(unittest.TestCase):
    """Bounded per-watched-CVE OSV enrichment + withdrawal (finding 1)."""

    def _osv(self, cve, **kw):
        base = {"id": cve, "modified": "2026-11-14T00:00:00.000Z",
                "published": "2026-11-01T00:00:00.000Z",
                "summary": "osv summary", "aliases": ["GHSA-x"],
                "references": [{"url": "https://osv.dev"}]}
        base.update(kw)
        return base

    def test_osv_enriches_watched_item(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-A"))
            ev = st.upsert_osv(self._osv("CVE-A"))
            self.assertEqual(ev, "UPDATED")
            item = st.items["CVE-A"]
            self.assertEqual(item["osv_summary"], "osv summary")
            self.assertIn({"provider": "osv", "url": aw.OSV_API + "CVE-A"},
                          item["sources"])

    def test_osv_withdrawal_flips_status(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-A"))
            ev = st.upsert_osv(self._osv(
                "CVE-A", withdrawn="2026-11-15T00:00:00.000Z"))
            self.assertEqual(ev, "WITHDRAWN")
            self.assertEqual(st.items["CVE-A"]["status"], "WITHDRAWN")
            self.assertEqual(st.items["CVE-A"]["withdrawn_evidence"],
                             ["CVE-A@2026-11-15T00:00:00.000Z"])

    def test_osv_identical_rerun_is_unchanged(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-A"))
            rec = self._osv("CVE-A")
            st.upsert_osv(dict(rec))
            ev = st.upsert_osv(dict(rec))
            self.assertEqual(ev, "UNCHANGED")

    def test_run_enriches_osv_per_watched_cve(self):
        """run() wires OSV per-CVE lookups for watched items (P4)."""
        today = dt.date.today().isoformat()
        kev = {"title": "KEV", "catalogVersion": "1", "dateReleased": "x",
               "count": 1, "vulnerabilities": [_kev("CVE-A", date_added=today)]}
        empty_nvd = {"resultsPerPage": 0, "startIndex": 0,
                     "totalResults": 0, "vulnerabilities": []}
        osv_rec = self._osv("CVE-A")
        t = RouteTransport()
        t.add(lambda u: "cisa.gov" in u, [kev, kev])
        t.add(lambda u: "cves/2.0" in u, [empty_nvd, empty_nvd])
        t.add(lambda u: "api.osv.dev" in u,
              [osv_rec, osv_rec])  # two runs -> idempotent second pass
        with TempStateDir() as tmp:
            run1 = aw.run(transport=paced(t), gh=None, state_dir=tmp.path,
                          enrich_min_interval=0)
            state = json.loads((tmp.path / "state.json").read_text())
            self.assertEqual(run1["providers"]["osv"], "OK")
            self.assertIn("osv_summary", state["items"]["CVE-A"])
            # snapshot stored under evidence/osv/
            files = list((tmp.path / "evidence" / "osv").glob("*.json"))
            self.assertTrue(files, "OSV evidence snapshot missing")

    def test_osv_failure_does_not_delete_existing_data(self):
        with TempStateDir() as tmp:
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-A"))
            st.upsert_osv(self._osv("CVE-A"))
            st.save()
            today = dt.date.today().isoformat()
            kev = {"title": "KEV", "catalogVersion": "1", "dateReleased": "x",
                   "count": 1, "vulnerabilities": [_kev("CVE-A",
                                                         date_added=today)]}
            empty_nvd = {"resultsPerPage": 0, "startIndex": 0,
                         "totalResults": 0, "vulnerabilities": []}
            t = RouteTransport()
            t.add(lambda u: "cisa.gov" in u, [kev])
            t.add(lambda u: "cves/2.0" in u, [empty_nvd])
            t.add(lambda u: "api.osv.dev" in u,
                  [aw.FetchError("osv down")])
            run1 = aw.run(transport=paced(t), gh=None, state_dir=tmp.path,
                          enrich_min_interval=0)
            state = json.loads((tmp.path / "state.json").read_text())
            self.assertTrue(str(run1["providers"]["osv"]).startswith("FAILED"))
            self.assertEqual(state["items"]["CVE-A"]["osv_summary"],
                             "osv summary")  # untouched by the failure


class TestExitCodeContract(unittest.TestCase):
    """P3: exit-code semantics — total provider failure with nothing
    already collected exits 1; any provider failure is nonzero so
    scheduled runs alert even with old state (exit 3); refusals exit 2."""

    def _main(self, transport):
        import io, contextlib
        with TempStateDir() as tmp:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = aw.main(["--state-dir", str(tmp.path)],
                               transport=transport)
        return code

    def test_total_failure_with_empty_state_exits_1(self):
        t = RouteTransport()
        t.add(lambda u: True, [aw.FetchError("all providers down")])
        transport = aw.Transport(transport=t, sleeper=lambda s: None,
                                 clock=lambda: 0.0, min_interval=0)
        code = self._main(transport)
        self.assertEqual(code, 1)

    def test_partial_failure_is_nonzero(self):
        """kev OK + nvd FAILED -> nonzero (exit 3): a scheduled run
        must visibly alert on any provider failure, not exit 0."""

        class KevOnly:
            def get_bytes(self, url):
                if "cisa.gov" in url:
                    return json.dumps({
                        "title": "KEV", "catalogVersion": "1",
                        "dateReleased": "x", "count": 0,
                        "vulnerabilities": []}).encode()
                raise aw.FetchError("nvd down")

        transport = aw.Transport(transport=KevOnly(), sleeper=lambda s: None,
                                 clock=lambda: 0.0, min_interval=0)
        code = self._main(transport)
        self.assertEqual(code, 3)

    def test_all_providers_failed_with_old_state_is_nonzero(self):
        """Defender probe P3 (the alerting hole): every provider fails
        while old promotable state exists — the run must NOT exit 0,
        because cron would read 'healthy' off stale data."""

        class AllFail:
            def get_bytes(self, url):
                raise aw.FetchError("provider down")

        with TempStateDir() as tmp:
            # seed old state with a promotable item
            st = aw.State(tmp.path)
            st.upsert_kev(_kev("CVE-OLD"))
            st.save()
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = aw.main(["--state-dir", str(tmp.path)],
                               transport=aw.Transport(
                                   transport=AllFail(),
                                   sleeper=lambda s: None,
                                   clock=lambda: 0.0, min_interval=0))
        self.assertEqual(code, 3)

    def test_healthy_run_exits_0(self):
        class AllOk:
            def get_bytes(self, url):
                if "cisa.gov" in url:
                    return json.dumps({
                        "title": "KEV", "catalogVersion": "1",
                        "dateReleased": "x", "count": 0,
                        "vulnerabilities": []}).encode()
                return json.dumps({
                    "resultsPerPage": 0, "startIndex": 0,
                    "totalResults": 0, "vulnerabilities": []}).encode()

        transport = aw.Transport(transport=AllOk(), sleeper=lambda s: None,
                                 clock=lambda: 0.0, min_interval=0)
        code = self._main(transport)
        self.assertEqual(code, 0)


    def test_refused_run_exits_2_without_touching_state(self):
        """Lock refusal / stale-gap refusal exit 2; state unchanged."""
        with TempStateDir() as tmp:
            tmp.path.mkdir(parents=True, exist_ok=True)
            (tmp.path / "run.lock").write_text("999\n")
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = aw.main(["--state-dir", str(tmp.path)])
            self.assertEqual(code, 2)
            self.assertFalse((tmp.path / "state.json").exists(),
                             "refused run must not write state")


class TestRawByteEvidence(unittest.TestCase):
    """Finding 6 (card directive): evidence snapshots must preserve and
    hash the ACTUAL raw response bytes from the wire — never reserialized
    JSON.  Raw wire evidence is kept distinct from the canonical derived
    state in state.json."""

    WIRE_KEV = (b'{"catalogVersion": "9", "title": "KEV", "dateReleased": "x",'
                b' "count": 0, "vulnerabilities": []}\n')
    WIRE_NVD_EMPTY = (b'{"resultsPerPage": 0, "startIndex": 0,'
                      b' "totalResults": 0, "vulnerabilities": []}')

    def _evidence_files(self, tmp, provider):
        return sorted(p for p in (tmp.path / "evidence" / provider)
                      .glob("*.json")
                      if not p.name.endswith(".sha256.json"))

    def test_kev_snapshot_stores_exact_wire_bytes(self):
        t = RouteTransport()
        t.add(lambda u: "cisa.gov" in u, [self.WIRE_KEV])
        t.add(lambda u: "cves/2.0" in u, [self.WIRE_NVD_EMPTY])
        with TempStateDir() as tmp:
            aw.run(transport=paced(t), gh=None, state_dir=tmp.path)
            files = self._evidence_files(tmp, "kev")
            self.assertEqual(len(files), 1)
            body = files[0].read_bytes()
            self.assertEqual(body, self.WIRE_KEV,
                             "snapshot must be the exact wire bytes")
            self.assertNotEqual(
                body,
                json.dumps(json.loads(body), indent=2, sort_keys=True)
                .encode("utf-8"),
                "snapshot must not be a canonical re-serialization")
            meta = json.loads(files[0].with_suffix(".sha256.json")
                              .read_text())
            self.assertEqual(meta["sha256"],
                             hashlib.sha256(self.WIRE_KEV).hexdigest())

    def test_nvd_page_snapshot_stores_exact_wire_bytes(self):
        page = (b'{"resultsPerPage": 1, "startIndex": 0, "totalResults": 1,'
                b' "vulnerabilities": [{"cve": {"id": "CVE-A",'
                b' "published": "2026-11-01T00:00:00.000",'
                b' "lastModified": "2026-11-01T00:00:00.000",'
                b' "vulnStatus": "Analyzed",'
                b' "descriptions": [{"lang": "en", "value": "d"}],'
                b' "metrics": {"cvssMetricV31": [{"cvssData":'
                b' {"baseScore": 8.8, "baseSeverity": "HIGH"}}]}}}]}\n')
        t = RouteTransport()
        t.add(lambda u: "cisa.gov" in u, [self.WIRE_KEV])
        t.add(lambda u: "cves/2.0" in u, [page])
        with TempStateDir() as tmp:
            aw.run(transport=paced(t), gh=None, state_dir=tmp.path)
            files = self._evidence_files(tmp, "nvd")
            self.assertEqual(len(files), 1,
                             "raw NVD page must be snapshotted")
            self.assertEqual(files[0].read_bytes(), page)
            meta = json.loads(files[0].with_suffix(".sha256.json")
                              .read_text())
            self.assertEqual(meta["sha256"], hashlib.sha256(page).hexdigest())

    def test_osv_snapshot_stores_exact_wire_bytes(self):
        today = dt.date.today().isoformat()
        kev = (b'{"catalogVersion": "1", "title": "KEV", "dateReleased": "x",'
               b' "count": 1, "vulnerabilities": [{"cveID": "CVE-A",'
               b' "dateAdded": "%s"}]}\n' % today.encode())
        osv_raw = (b'{"id": "CVE-A", "modified":'
                   b' "2026-11-14T00:00:00.000Z",'
                   b' "summary": "osv summary"}\n')
        t = RouteTransport()
        t.add(lambda u: "cisa.gov" in u, [kev])
        t.add(lambda u: "cves/2.0" in u, [self.WIRE_NVD_EMPTY])
        t.add(lambda u: "api.osv.dev" in u, [osv_raw])
        with TempStateDir() as tmp:
            aw.run(transport=paced(t), gh=None, state_dir=tmp.path,
                   enrich_min_interval=0)
            files = self._evidence_files(tmp, "osv")
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].read_bytes(), osv_raw)
            meta = json.loads(files[0].with_suffix(".sha256.json")
                              .read_text())
            self.assertEqual(meta["sha256"],
                             hashlib.sha256(osv_raw).hexdigest())

    def test_ghsa_snapshot_stores_exact_gh_stdout_bytes(self):
        today = dt.date.today().isoformat()
        kev = (b'{"catalogVersion": "1", "title": "KEV", "dateReleased": "x",'
               b' "count": 1, "vulnerabilities": [{"cveID": "CVE-A",'
               b' "dateAdded": "%s"}]}\n' % today.encode())
        ghsa_raw = (b'[{"ghsa_id": "G-1", "cve_id": "CVE-A",'
                    b' "severity": "high",'
                    b' "updated_at": "2026-11-14T00:00:00Z"}]\n')

        def runner(args):
            return ghsa_raw.decode("utf-8")

        gh = aw.GhCli(runner=runner)
        t = RouteTransport()
        t.add(lambda u: "cisa.gov" in u, [kev])
        t.add(lambda u: "cves/2.0" in u, [self.WIRE_NVD_EMPTY])
        t.add(lambda u: "api.osv.dev" in u, [http_error(404)])
        with TempStateDir() as tmp:
            aw.run(transport=paced(t), gh=gh, state_dir=tmp.path,
                   enrich_min_interval=0)
            files = self._evidence_files(tmp, "ghsa")
            self.assertEqual(len(files), 1,
                             "raw gh api stdout must be snapshotted")
            self.assertEqual(files[0].read_bytes(), ghsa_raw)
            meta = json.loads(files[0].with_suffix(".sha256.json")
                              .read_text())
            self.assertEqual(meta["sha256"],
                             hashlib.sha256(ghsa_raw).hexdigest())

    def test_docs_and_docstring_claim_raw_wire_bytes(self):
        src = (ROOT / "tools" / "advisory_watch.py").read_text()
        self.assertIn("raw response bytes", src)
        self.assertNotIn("canonicalized JSON", src)
        ops = (ROOT / "docs" / "advisory-watch-operations.md").read_text()
        self.assertIn("raw response bytes", ops)
        self.assertNotIn("canonicalized provider JSON", ops)
        self.assertNotIn("not byte-verbatim", ops)


import hashlib  # noqa: E402  (used above)


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
            v = {
                "reproduction": {
                    "env": "local authorized fixture", "component": "vulnserver",
                    "version": "6.0.0", "affected_version": "6.0.0",
                    "config": "official defaults", "command": "repro-cmd",
                    "result": "issue reproduced"},
                "control": {"version": "6.2.7.1", "result": "no repro"},
                "independent_review": {"reviewer": "r", "verdict": "confirmed",
                                       "date": "2026-11-15"},
            }
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
