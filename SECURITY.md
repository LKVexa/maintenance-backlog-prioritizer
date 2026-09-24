# Security and interpretation boundaries

The library produces advisory data and performs no maintenance writes. Approval
records are caller assertions: role and reviewer name are not authentication.
Identity_verified remains false. A digest binds the reviewed content but cannot
stop a caller from constructing new content and hashes. Authentication, access
control, reviewer authority and execution are external responsibilities.

Environment labels and inventory are unverified caller data. Explicit scope
prevents simple cross-environment grouping; unscoped legacy signals remain less
precise and carry missing-context notices. Distinct raw records are counted as
distinct evidence, not necessarily independent observations or incidents.

Priority scores are provisional arithmetic, not calibrated probabilities. Unknown
inventory defaults to lower exposure and is exposed in missing context. Scores
cannot establish that an item is safe or that remediation should be automatic.
Ambiguous ownership requires human resolution.

Finite JSON, count/size limits, strict derived-field checks and detached outputs
cover normal API use. They do not isolate malicious in-process Python code,
concurrent mutation, arbitrarily deep input, or guarantee process memory quotas.
Exposed services need request limits and OS isolation before parsing input.

Raw evidence, service names, owners and recommendation text are not redacted.
Sanitize before sharing or logging. Diagnostics omit unknown raw kind/severity
values but ordinary artifacts intentionally retain caller data.

There are no external runtime dependencies. Build tooling is bounded; no build-tool
vulnerability scan is claimed. Report defects privately with sanitized reproductions.
