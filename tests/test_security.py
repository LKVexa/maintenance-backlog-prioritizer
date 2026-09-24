import copy
import json
import unittest
from unittest.mock import patch
from mbp.core import (build_service_map, normalize_signals, dedupe_to_actions,
    prioritize, draft_recommendations, advance_state, _digest, SEVERITY_RANK)
from tests.test_mbp import SERVICES, SIGNALS

class SecurityRegressions(unittest.TestCase):
    def actions(self, signals=None):
        return dedupe_to_actions(normalize_signals(SIGNALS[:4] if signals is None else signals)["queue"])

    def recommendation(self):
        service_map = build_service_map(SERVICES)
        return draft_recommendations(prioritize(self.actions(), service_map), service_map)["recommendations"][0]

    def approval(self, rec):
        return {"role": "human", "approver": "reviewer", "recommendation_digest": rec["recommendation_digest"]}

    def test_unidentified_inventory_rejected(self):
        with self.assertRaises(ValueError):
            build_service_map([{"environment": "prod"}])

    def test_invalid_inventory_shapes_rejected(self):
        for value in (None, {}, [None], [{"service": []}], [{"service": "api", "owner": True}]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                build_service_map(value)

    def test_incomplete_inventory_kept(self):
        entry = build_service_map([{"service": "api"}])["api"]
        self.assertEqual(entry["gaps"], ["artifact", "environment", "owner", "runtime"])
        self.assertEqual(entry["scopes"][0]["environment"], None)

    def test_inventory_scopes_preserve_owner_association(self):
        records = copy.deepcopy(SERVICES[:2])
        records[1]["owner"] = "stage-team"
        inventory = build_service_map(records)
        owners = {x["environment"]: x["owners"] for x in inventory["api"]["scopes"]}
        self.assertEqual(owners, {"prod": ["team-core"], "staging": ["stage-team"]})

    def test_invalid_signal_shapes_flagged(self):
        result = normalize_signals([None, [], 1, {}])
        self.assertEqual(result["queue"], [])
        self.assertEqual(len(result["flagged_signals"]), 4)

    def test_invalid_label_values_flagged(self):
        for field in ("kind", "severity", "service", "subject", "source", "environment"):
            for value in (None, [], True, "", "a\n"):
                with self.subTest(field=field, value=value):
                    result = normalize_signals([dict(SIGNALS[0], **{field: value})])
                    self.assertEqual(result["queue"], [])
                    self.assertTrue(result["flagged_signals"])

    def test_nonfinite_payload_flagged(self):
        result = normalize_signals([dict(SIGNALS[0], extra=float("nan"))])
        self.assertEqual(result["queue"], [])
        self.assertIn("nonfinite", result["flagged_signals"][0]["reason"])

    def test_unknown_values_are_not_echoed(self):
        result = normalize_signals([dict(SIGNALS[0], kind="credential-example")])
        self.assertNotIn("credential-example", json.dumps(result))

    def test_record_count_limit(self):
        with patch("mbp.core.MAX_RECORDS", 1), self.assertRaises(ValueError):
            normalize_signals(SIGNALS[:2])

    def test_record_byte_limit(self):
        with patch("mbp.core.MAX_RECORD_BYTES", 10):
            result = normalize_signals([SIGNALS[0]])
        self.assertEqual(result["queue"], [])

    def test_total_signal_limit_raises(self):
        records = [dict(SIGNALS[0], extra="x"*100) for _ in range(10)]
        with patch("mbp.core.MAX_BYTES", 400), self.assertRaises(ValueError):
            normalize_signals(records)

    def test_environment_separates_root_actions(self):
        result = self.actions([dict(SIGNALS[0], environment=env) for env in ("prod", "stage")])
        self.assertEqual(len(result), 2)
        self.assertNotEqual(result[0]["action_id"], result[1]["action_id"])

    def test_unscoped_action_distinct_from_scoped(self):
        self.assertEqual(len(self.actions([SIGNALS[0], dict(SIGNALS[0], environment="prod")])), 2)

    def test_replayed_identical_signal_does_not_raise_score(self):
        inventory = build_service_map(SERVICES)
        self.assertEqual(prioritize(self.actions([SIGNALS[0]]), inventory),
                         prioritize(self.actions([SIGNALS[0]]*10), inventory))

    def test_distinct_source_evidence_kept(self):
        result = self.actions(SIGNALS[:2])
        self.assertEqual(result[0]["occurrences"], 2)
        self.assertEqual(result[0]["severity"], "critical")

    def test_permutation_has_identical_actions(self):
        self.assertEqual(self.actions(SIGNALS[:4]), self.actions(SIGNALS[:4][::-1]))

    def test_full_digest_identity(self):
        for action in self.actions():
            self.assertEqual(len(action["action_id"]), 68)

    def test_queue_mutation_cannot_change_action_evidence(self):
        queue = normalize_signals(SIGNALS[:1])["queue"]
        result = dedupe_to_actions(queue)
        queue[0]["provenance"]["raw"]["subject"] = "changed"
        self.assertNotEqual(result[0]["evidence"][0]["raw"]["subject"], "changed")

    def test_tampered_normalized_fields_rejected(self):
        queue = normalize_signals(SIGNALS[:1])["queue"]
        queue[0]["severity"] = "low"
        with self.assertRaises(ValueError):
            dedupe_to_actions(queue)

    def test_tampered_raw_digest_rejected(self):
        queue = normalize_signals(SIGNALS[:1])["queue"]
        queue[0]["provenance"]["raw_digest"] = "sha256:"+"0"*64
        with self.assertRaises(ValueError):
            dedupe_to_actions(queue)

    def test_forged_action_fields_rejected(self):
        for field, value in (("severity", "low"), ("occurrences", 999), ("occurrences", True),
                             ("action_id", "forged")):
            actions = self.actions()
            actions[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                prioritize(actions, build_service_map(SERVICES))

    def test_duplicate_action_ids_rejected(self):
        actions = self.actions()
        with self.assertRaises(ValueError):
            prioritize([actions[0], actions[0]], build_service_map(SERVICES))

    def test_invalid_effort_hint_rejected(self):
        actions = self.actions()
        with self.assertRaises(ValueError):
            prioritize(actions, build_service_map(SERVICES), {actions[0]["action_id"]: "tiny"})

    def test_unknown_effort_action_rejected(self):
        with self.assertRaises(ValueError):
            prioritize(self.actions(), build_service_map(SERVICES), {"unknown": "small"})

    def test_scoped_stage_signal_does_not_inherit_prod_exposure(self):
        records = copy.deepcopy(SERVICES[:2])
        records[1]["owner"] = "stage-team"
        inventory = build_service_map(records)
        actions = self.actions([dict(SIGNALS[0], environment="staging")])
        result = prioritize(actions, inventory)
        self.assertEqual(result[0]["score_components"]["exposure"], 1)
        rec = draft_recommendations(result, inventory)["recommendations"][0]
        self.assertEqual(rec["whom_to_contact"], "stage-team")

    def test_ambiguous_owner_is_unknown(self):
        inventory = build_service_map(SERVICES+[dict(SERVICES[0], owner="other-team")])
        recs = draft_recommendations(prioritize(self.actions(), inventory), inventory)
        rec = next(r for r in recs["recommendations"] if len(r["owner_candidates"]) > 1)
        self.assertIn("UNKNOWN", rec["whom_to_contact"])
        self.assertIn("ambiguous service owner", rec["missing_context"])

    def test_unscoped_multi_environment_signal_is_explicit(self):
        rec = self.recommendation()
        self.assertIn("signal environment", rec["missing_context"])

    def test_missing_inventory_is_explicit(self):
        recs = draft_recommendations(prioritize(self.actions(), {}), {})
        self.assertTrue(any(x["missing"] == "service inventory" for x in recs["missing_context"]))

    def test_score_is_recomputable(self):
        for action in prioritize(self.actions(), build_service_map(SERVICES)):
            c = action["score_components"]
            self.assertEqual(action["priority_score"], c["severity_rank"]*2 +
                (c["exposure"]+c["recurrence"])*1.5 - c["effort_rank"]*0.5)

    def test_rank_configuration_cannot_be_mutated(self):
        with self.assertRaises(TypeError):
            SEVERITY_RANK["critical"] = 0

    def test_forged_priority_rejected(self):
        inventory = build_service_map(SERVICES)
        result = prioritize(self.actions(), inventory)
        result[0]["priority_score"] = 100
        with self.assertRaises(ValueError):
            draft_recommendations(result, inventory)

    def test_changed_inventory_invalidates_prioritization(self):
        inventory = build_service_map(SERVICES)
        result = prioritize(self.actions(), inventory)
        inventory["api"]["owners"] = ["new-team"]
        with self.assertRaises(ValueError):
            draft_recommendations(result, inventory)

    def test_approval_requires_digest_binding(self):
        with self.assertRaises(ValueError):
            advance_state(self.recommendation(), {"role": "human", "approver": "reviewer"})

    def test_approval_for_different_recommendation_rejected(self):
        rec = self.recommendation()
        approval = self.approval(rec)
        approval["recommendation_digest"] = "sha256:"+"0"*64
        with self.assertRaises(ValueError):
            advance_state(rec, approval)

    def test_tampered_recommendation_rejected(self):
        rec = self.recommendation()
        approval = self.approval(rec)
        rec["what"] = "different maintenance"
        with self.assertRaises(ValueError):
            advance_state(rec, approval)

    def test_approval_is_not_identity_authentication(self):
        rec = self.recommendation()
        reviewed = advance_state(rec, self.approval(rec))
        self.assertFalse(reviewed["approval"]["identity_verified"])
        self.assertEqual(reviewed["approval"]["reviewed_digest"], rec["recommendation_digest"])

    def test_approval_cannot_replay_state_transition(self):
        rec = self.recommendation()
        approval = self.approval(rec)
        reviewed = advance_state(rec, approval)
        with self.assertRaises(ValueError):
            advance_state(reviewed, approval)

