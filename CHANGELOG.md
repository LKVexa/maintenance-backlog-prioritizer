# 0.1.2a1 — 2026-09-23

- Retain scoped inventory and environment-aware full action identities.
- Deduplicate exact evidence and validate derived identity, severity and count.
- Bound finite JSON input; detach evidence and expose ambiguous ownership.
- Recompute scores before drafting; bind review state changes to recommendation digest.
- Add 37 regressions, packaging, Apache 2.0 LICENSE/NOTICE, README and CI.
- Compatibility: rebuild actions and drafts; include reviewed digest in approvals.

# Changelog — Maintenance Backlog Prioritizer (JY-S008-P001)

## 0.1.1-partial — 2026-09-14 (audit A009, maintenance repairs only)

Baseline fingerprint: build-0001 `product.zip`
sha256 `b89d47da6bcefe64de3d03613b37002de1fca9f6b256da3d8858519d53bd81cd`
(7685 bytes), baseline version `0.1.0-partial`, 12/12 tests passing,
no user edits found.

All findings were reproduced on the baseline with live probes before
being fixed (probe output preserved in audit records).

- **A009-F1 (aliasing / evidence integrity, high):**
  `normalize_signals` stored the caller's mutable signal dict as
  `provenance.raw` by reference. Observed: mutating the input after the
  call silently changed stored evidence so `raw_digest` no longer
  matched `raw`. Expected: evidence is a snapshot; digest always matches.
  Fixed with `copy.deepcopy` of the signal.
- **A009-F2 (aliasing / output isolation, high):** `prioritize`,
  `draft_recommendations`, and `advance_state` shared the same evidence
  list objects with their inputs. Observed: appending forged evidence to
  a recommendation mutated the deduped action; clearing an advanced
  record's evidence emptied the draft's. Expected: outputs are isolated.
  Fixed with deep copies at each boundary.
- **A009-F3 (error contract, medium):** a signal containing a
  non-JSON-serializable value crashed `normalize_signals` with a bare
  `TypeError`, aborting the whole batch. Expected per module contract:
  bad signals are flagged with a reason, never coerced or fatal. Fixed:
  such signals are flagged `unserializable signal` and processing
  continues.
- **A009-F4 (approval validation, medium):** `advance_state` accepted
  `approver: ""` or `approver: None`, producing an approved record with
  no accountable human. Expected: a state advance names a real approver.
  Fixed: approver must be a non-empty string, else `ValueError`.

Compatibility: no public API removed or renamed; all baseline behavior
preserved except the reproduced defects above. All 12 baseline tests
pass unchanged; 4 focused hardening tests added (16 total).

Rollback: restore build-0001 `product.zip`
(sha256 `b89d47da...bd81cd`); no data migration involved.
