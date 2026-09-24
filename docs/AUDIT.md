# Audit and hardening — 0.1.2a1

Date: 2026-09-23. Source: JY-S008-P001 / 0.1.1-partial / run-0001 / product.
Reviewed all inventory, normalization, deduplication, scoring and review-state code.
Original source remains separate from the maintenance checkout.

## Repaired findings

- Inventory records without identity were silently dropped; malformed fields could
  crash. Missing identity now fails, while identifiable partial records retain gaps.
- Inventory aggregation lost environment/owner association and signals from
  different environments merged. Scoped inventory and action identity now retain
  boundaries, with explicit unknown context for unscoped or missing inventory.
- Unknown types/nonfinite data and unbounded input could enter hashes or scoring.
  Bounded finite-JSON validation now checks every public pipeline stage.
- Action IDs used truncated hashes. Full environment-aware identities replace them.
- Exact replay increased occurrence pressure and evidence ordering depended on
  caller order. Identical raw records now deduplicate, with stable evidence order.
- Dedupe evidence aliased input queue objects; outputs now use detached snapshots.
- Forged normalized fields, evidence digests, action counts and IDs were trusted.
  They are recomputed from raw evidence at each stage before downstream use.
- Invalid effort silently defaulted to medium. Invalid values and unknown action
  hints now raise. Score components are explicit and ranking tables immutable.
- Multiple owners silently selected the first. Ambiguity is exposed with candidates.
- Drafts accepted arbitrary priority scores/context. Scores and context are now
  recomputed before drafting and mismatches rejected.
- Any named human record advanced arbitrary recommendation state without content
  binding. Transitions now require a valid draft and matching reviewed digest.
  Identity authentication remains explicitly external and unverified.

## Release and verification

16 inherited tests passed before changes. Approval and diagnostic assertions were
updated for deliberate stricter contracts. 53 source/installed-wheel tests pass,
including 37 new regressions. Historical check evidence is retained separately.
CI covers Linux Python 3.10/3.12/3.14 and Windows Python 3.12.

Version 0.1.1-partial -> 0.1.2a1. Regenerate action IDs and all downstream artifacts;
approval requests now require recommendation_digest. Added packaging, pinned-action
CI, Apache 2.0 LICENSE/NOTICE naming RUSSELL PHILIP SMITHSON, README and security docs.

There are no third-party runtime dependencies to upgrade or scan. No build-tool
vulnerability scan is claimed. This remains an advisory partial prototype; the
original 215-module roadmap and production release gates are not completed.
