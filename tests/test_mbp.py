import unittest

from mbp.core import (advance_state, build_service_map, dedupe_to_actions,
                      draft_recommendations, normalize_signals, prioritize)

SERVICES = [
    {"service": "api", "environment": "prod", "owner": "team-core",
     "runtime": "python3.11", "artifact": "api:1.4.0"},
    {"service": "api", "environment": "staging", "owner": "team-core",
     "runtime": "python3.11", "artifact": "api:1.5.0-rc"},
    {"service": "batch", "environment": "prod", "owner": None,
     "runtime": "java17", "artifact": "batch:2.2"},
]

SIGNALS = [
    {"source": "scanner", "kind": "cve", "service": "api",
     "subject": "openssl 3.0.1 CVE-2026-1234", "severity": "critical"},
    {"source": "scanner-2", "kind": "security-alert", "service": "api",
     "subject": "openssl 3.0.1 CVE-2026-1234", "severity": "high"},
    {"source": "bot", "kind": "outdated-dependency", "service": "api",
     "subject": "requests 2.28 -> 2.32", "severity": "low"},
    {"source": "monitor", "kind": "cert-expiry", "service": "batch",
     "subject": "batch.example.com TLS cert", "severity": "high"},
    {"source": "wiki", "kind": "vibes", "service": "api",
     "subject": "feels old", "severity": "high"},
    {"source": "scanner", "kind": "cve", "service": "api",
     "subject": "libxml CVE-2026-9", "severity": "unknowable"},
    {"source": "scanner", "kind": "cve", "service": "api"},
]


class ServiceMap(unittest.TestCase):
    def test_mapping_and_gaps(self):
        m = build_service_map(SERVICES)
        self.assertEqual(m["api"]["environments"], ["prod", "staging"])
        self.assertEqual(m["api"]["owners"], ["team-core"])
        self.assertIn("owner", m["batch"]["gaps"])       # kept, gap listed
        self.assertEqual(m["api"]["gaps"], [])


class Normalize(unittest.TestCase):
    def setUp(self):
        self.res = normalize_signals(SIGNALS)

    def test_unified_kinds(self):
        kinds = {e["kind"] for e in self.res["queue"]}
        self.assertEqual(kinds, {"vulnerability", "dependency-update",
                                 "certificate"})

    def test_unknowns_flagged_not_coerced(self):
        reasons = " | ".join(f["reason"] for f in self.res["flagged_signals"])
        self.assertIn("unknown kind", reasons)
        self.assertIn("unknown severity", reasons)
        self.assertIn("missing fields", reasons)
        self.assertEqual(len(self.res["queue"]), 4)

    def test_provenance(self):
        for e in self.res["queue"]:
            self.assertTrue(e["provenance"]["raw_digest"].startswith("sha256:"))


class Dedupe(unittest.TestCase):
    def test_repeated_alerts_collapse_to_root_action(self):
        actions = dedupe_to_actions(normalize_signals(SIGNALS)["queue"])
        self.assertEqual(len(actions), 3)
        cve = next(a for a in actions if "CVE-2026-1234" in a["subject"])
        self.assertEqual(cve["occurrences"], 2)
        self.assertEqual(cve["severity"], "critical")    # highest observed
        self.assertEqual(len(cve["evidence"]), 2)        # both provenances kept


class Prioritize(unittest.TestCase):
    def setUp(self):
        self.smap = build_service_map(SERVICES)
        self.actions = dedupe_to_actions(normalize_signals(SIGNALS)["queue"])
        self.pri = prioritize(self.actions, self.smap)

    def test_order_and_rationale(self):
        self.assertIn("CVE-2026-1234", self.pri[0]["subject"])   # critical first
        subjects = [p["subject"] for p in self.pri]
        self.assertGreater(subjects.index("requests 2.28 -> 2.32"),
                           subjects.index("batch.example.com TLS cert"))
        for p in self.pri:
            self.assertIn("severity=", p["rationale"])
            self.assertIn("effort=", p["rationale"])

    def test_effort_hint_lowers_score(self):
        cve_id = self.pri[0]["action_id"]
        harder = prioritize(self.actions, self.smap,
                            effort_hints={cve_id: "large"})
        easier = prioritize(self.actions, self.smap,
                            effort_hints={cve_id: "small"})
        h = next(a for a in harder if a["action_id"] == cve_id)
        e = next(a for a in easier if a["action_id"] == cve_id)
        self.assertLess(h["priority_score"], e["priority_score"])

    def test_deterministic(self):
        self.assertEqual(self.pri, prioritize(self.actions, self.smap))


class Recommendations(unittest.TestCase):
    def setUp(self):
        smap = build_service_map(SERVICES)
        actions = dedupe_to_actions(normalize_signals(SIGNALS)["queue"])
        self.recs = draft_recommendations(prioritize(actions, smap), smap)

    def test_what_why_how_whom(self):
        r = self.recs["recommendations"][0]
        for f in ("what", "why", "how", "whom_to_contact"):
            self.assertTrue(r[f])
        self.assertEqual(r["whom_to_contact"], "team-core")

    def test_missing_owner_exposed_not_invented(self):
        cert = next(r for r in self.recs["recommendations"]
                    if "TLS cert" in r["what"])
        self.assertIn("UNKNOWN", cert["whom_to_contact"])
        self.assertTrue(any(m["missing"] == "service owner"
                            for m in self.recs["missing_context"]))

    def test_draft_only_and_no_write_api(self):
        self.assertTrue(self.recs["read_only"] and self.recs["draft_only"])
        for r in self.recs["recommendations"]:
            self.assertEqual(r["state"], "DRAFT")
        import mbp.core as m
        for name in dir(m):
            for bad in ("patch", "upgrade_", "deploy", "apply", "remediate",
                        "configure"):
                self.assertNotIn(bad, name.lower())

    def test_human_approval_advances_state_only(self):
        r = self.recs["recommendations"][0]
        with self.assertRaises(ValueError):
            advance_state(r, {"role": "model"})
        approved = advance_state(r, {"role": "human", "approver": "ops-lead",
                                     "recommendation_digest": r["recommendation_digest"]})
        self.assertEqual(approved["state"], "APPROVED_FOR_HUMAN_EXECUTION")
        self.assertIn("external, human-controlled",
                      approved["approval"]["note"])
        self.assertEqual(r["state"], "DRAFT")     # original untouched


if __name__ == "__main__":
    unittest.main()


class Hardening0_1_1(unittest.TestCase):
    """A009 audit fixes (v0.1.1-partial): aliasing, error contract,
    approval validation."""

    SIG = {"source": "scanner", "kind": "cve", "service": "api",
           "subject": "x", "severity": "high"}
    SVC = [{"service": "api", "environment": "prod", "owner": "t",
            "runtime": "r", "artifact": "a"}]

    def test_f1_raw_evidence_isolated_from_caller_mutation(self):
        sig = dict(self.SIG)
        res = normalize_signals([sig])
        prov = res["queue"][0]["provenance"]
        sig["severity"] = "low"
        self.assertEqual(prov["raw"]["severity"], "high")
        from mbp.core import _digest
        self.assertEqual(_digest(prov["raw"]), prov["raw_digest"])

    def test_f2_output_evidence_isolated(self):
        smap = build_service_map(self.SVC)
        actions = dedupe_to_actions(normalize_signals([dict(self.SIG)])["queue"])
        pri = prioritize(actions, smap)
        pri[0]["evidence"].append({"forged": True})
        self.assertEqual(len(actions[0]["evidence"]), 1)
        recs = draft_recommendations(prioritize(actions, smap), smap)
        r = recs["recommendations"][0]
        r["evidence"].append({"forged": True})
        self.assertEqual(len(actions[0]["evidence"]), 1)
        with self.assertRaises(ValueError):
            advance_state(r, {"role": "human", "approver": "lead",
                               "recommendation_digest": r["recommendation_digest"]})
        r = draft_recommendations(prioritize(actions, smap), smap)["recommendations"][0]
        adv = advance_state(r, {"role": "human", "approver": "lead",
                               "recommendation_digest": r["recommendation_digest"]})
        adv["evidence"].clear()
        self.assertTrue(r["evidence"])           # original draft untouched

    def test_f3_unserializable_signal_flagged_not_crash(self):
        bad = dict(self.SIG, subject={1, 2})
        res = normalize_signals([bad, dict(self.SIG)])
        self.assertEqual(len(res["queue"]), 1)   # good signal still processed
        self.assertTrue(any("unserializable" in f["reason"]
                            for f in res["flagged_signals"]))

    def test_f4_blank_or_nonstring_approver_rejected(self):
        rec = {"state": "DRAFT"}
        for approver in ("", "   ", None, 7):
            with self.assertRaises(ValueError):
                advance_state(rec, {"role": "human", "approver": approver})
        with self.assertRaises(ValueError):
            advance_state(rec, {"role": "human", "approver": "ops-lead"})
