# Maintenance Backlog Prioritizer

**0.1.2a1 — experimental partial candidate, JY-S008-P001**

A pure Python advisory library for service inventory, maintenance signal
normalization, evidence deduplication, priority scores and draft recommendations.
It performs no retrieval, patching, deployment, configuration changes or messaging.

## Install and use

Python 3.10 or newer; no third-party runtime dependencies.

~~~sh
python -m pip install .
python -m unittest discover -s tests -t .
~~~

~~~python
from mbp.core import (build_service_map, normalize_signals, dedupe_to_actions,
                      prioritize, draft_recommendations, advance_state)

inventory = build_service_map([{
    "service": "api", "environment": "prod", "owner": "platform",
    "runtime": "python", "artifact": "api:v1"
}])
normalized = normalize_signals([{
    "source": "scanner", "kind": "cve", "service": "api", "environment": "prod",
    "subject": "example advisory", "severity": "high"
}])
actions = dedupe_to_actions(normalized["queue"])
drafts = draft_recommendations(prioritize(actions, inventory), inventory)
reviewed = drafts["recommendations"][0]
# Only after external human review and caller-side identity verification:
recorded = advance_state(reviewed, {
    "role": "human", "approver": "reviewer",
    "recommendation_digest": reviewed["recommendation_digest"]
})
~~~

Inspect flagged_signals and missing_context before using the result. The review
record changes only returned data. Identity remains caller-asserted and the
approval includes identity_verified: false; execution remains external.

## Evidence and environments

Root action identity covers kind, service, subject and optional environment with
full SHA-256. Production, staging and unscoped signals form separate actions.
Exact canonical duplicates count once; distinct records preserve all evidence.
Severity uses the highest observed rank. Evidence ordering is deterministic.

Service inventory keeps environment-specific owners, runtimes, artifacts and gaps,
alongside service-level aggregates. Explicitly scoped signals use only matching
inventory. Unknown environment inventory remains explicit. Legacy unscoped signals
use service-wide exposure and report missing signal environment when multiple
environments exist. This is an advisory fallback, not proof of exposure.

Multiple candidate owners are reported as ambiguous; no arbitrary owner is selected.
Incomplete identifiable inventory is retained. Records without a service identity
raise ValueError so inventory cannot silently lose them.

Every pipeline stage verifies raw evidence digests and derived fields. Drafting
recomputes scores and service context; stale or altered priority data fails.
Approval requires the exact recommendation digest, a named reviewer, a human role
assertion and DRAFT state. Edited drafts and repeated state transitions are rejected.
Hashes bind content; they do not establish authenticity or access authority.

## Score and input contracts

Score = 2 × severity_rank + 1.5 × (exposure + recurrence) − 0.5 × effort_rank.

Severity ranks low/medium/high/critical as 1/2/3/4. Exposure is 2 for known
prod/production inventory, otherwise 1. Recurrence is min(distinct_evidence−1, 2)
× 0.5. Effort ranks small/medium/large as 1/2/3, default medium. Components and
rationale are returned. Invalid or unknown-action effort hints raise ValueError.
These heuristic scores are not calibrated risk probabilities. Unknown inventory
can lower exposure scores and must be reviewed.

Inputs must be finite JSON data. Lists are limited to 10,000 entries, labels to
512 characters, individual signals to 256 KiB, and serialized aggregates/models
to 16 MiB. Invalid signals are flagged individually; exceeding the combined signal
limit raises ValueError. Other malformed API input raises ValueError. Returned
evidence is detached from caller-owned objects.

## Compatibility and remaining scope

Version 0.1.1-partial -> 0.1.2a1 changes action IDs to full, environment-aware
digests and changes recurrence to distinct evidence. Rebuild saved actions,
scores and recommendations. Approval requests must now include the reviewed digest.
Updated assertions in inherited tests reflect these deliberate contracts.

53 tests include 16 inherited checks and 37 regressions. Source and installed-wheel
checks are in [CHECK_RUNS](docs/CHECK_RUNS.json); see [AUDIT](docs/AUDIT.md) and
[SECURITY](SECURITY.md). CI covers Linux Python 3.10/3.12/3.14 and Windows Python 3.12.

The original 215-module roadmap remains broader than these deterministic slices.
Live connectors, service/storage layers, human-review UI, identity authentication,
model-based scoring and production readiness gates are not implemented.

## License

Copyright 2026 **RUSSELL PHILIP SMITHSON**.
[Apache License 2.0](LICENSE), with [NOTICE](NOTICE).
No third-party code is vendored.
