"""Bounded advisory maintenance prioritization; no maintenance execution."""
from __future__ import annotations
import hashlib
import json
from types import MappingProxyType

VERSION = "0.1.2a1"
MAX_RECORDS = 10000
MAX_BYTES = 16 * 1024 * 1024
MAX_RECORD_BYTES = 256 * 1024
SEVERITY_RANK = MappingProxyType({"critical": 4, "high": 3, "medium": 2, "low": 1})
EFFORT_RANK = MappingProxyType({"small": 1, "medium": 2, "large": 3})
KIND_MAP = MappingProxyType({
    "cve": "vulnerability", "vuln": "vulnerability", "security-alert": "vulnerability",
    "vulnerability": "vulnerability", "eol": "end-of-life", "end_of_life": "end-of-life",
    "end-of-life": "end-of-life", "deprecation": "deprecation", "deprecated-api": "deprecation",
    "outdated-dependency": "dependency-update", "dependency": "dependency-update",
    "dependency-update": "dependency-update", "cert-expiry": "certificate",
    "certificate": "certificate", "disk": "capacity", "capacity": "capacity"})
REQUIRED_SERVICE_FIELDS = {"service", "environment", "owner", "runtime", "artifact"}
REQUIRED_SIGNAL_FIELDS = {"source", "kind", "service", "subject", "severity"}

def _encoded(value):
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError):
        raise ValueError("unserializable or nonfinite JSON data") from None
    if len(encoded) > MAX_BYTES:
        raise ValueError("JSON size limit exceeded")
    return encoded

def _snapshot(value):
    return json.loads(_encoded(value))

def _digest(value):
    return "sha256:" + hashlib.sha256(_encoded(value)).hexdigest()

def _label(value):
    if type(value) is not str or not value.strip() or len(value) > 512 or any(ord(c) < 32 for c in value):
        raise ValueError("required label must be a nonempty bounded string")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ValueError("label contains invalid Unicode") from None
    return value

def _records(value):
    if type(value) is not list or len(value) > MAX_RECORDS:
        raise ValueError("records must be a bounded list")
    return value

def build_service_map(records):
    """Keep incomplete identifiable records; reject records without service identity."""
    records = _snapshot(_records(records))
    services = {}
    for record in records:
        if type(record) is not dict:
            raise ValueError("service record must be an object")
        name = _label(record.get("service"))
        for field in REQUIRED_SERVICE_FIELDS - {"service"}:
            if record.get(field) is not None and record[field] != "":
                _label(record[field])
        entry = services.setdefault(name, {"environments": set(), "owners": set(),
            "runtimes": set(), "artifacts": set(), "gaps": set(), "scopes": {}})
        missing = REQUIRED_SERVICE_FIELDS - {key for key, value in record.items() if value}
        entry["gaps"].update(missing)
        environment = record.get("environment") or None
        scope = entry["scopes"].setdefault(environment, {"owners": set(), "runtimes": set(),
                                                       "artifacts": set(), "gaps": set()})
        scope["gaps"].update(missing)
        if environment:
            entry["environments"].add(environment)
        for field, bucket in (("owner", "owners"), ("runtime", "runtimes"), ("artifact", "artifacts")):
            if record.get(field):
                entry[bucket].add(record[field])
                scope[bucket].add(record[field])
    return {name: {**{key: sorted(value) for key, value in entry.items() if key != "scopes"},
                   "scopes": [{"environment": env, **{key: sorted(value) for key, value in scope.items()}}
                              for env, scope in sorted(entry["scopes"].items(), key=lambda item: item[0] or "")]}
            for name, entry in sorted(services.items())}

def _normalized(signal):
    if len(_encoded(signal)) > MAX_RECORD_BYTES:
        raise ValueError("signal size limit exceeded")
    signal = _snapshot(signal)
    if type(signal) is not dict:
        raise ValueError("signal must be an object")
    missing = sorted(REQUIRED_SIGNAL_FIELDS - set(signal))
    if missing:
        raise ValueError("missing fields " + ", ".join(missing))
    for field in REQUIRED_SIGNAL_FIELDS:
        _label(signal[field])
    kind = KIND_MAP.get(signal["kind"].lower())
    severity = signal["severity"].lower()
    if kind is None:
        raise ValueError("unknown kind")
    if severity not in SEVERITY_RANK:
        raise ValueError("unknown severity")
    environment = signal.get("environment")
    if "environment" in signal:
        _label(environment)
    return {"kind": kind, "service": signal["service"], "subject": signal["subject"],
            "environment": environment, "severity": severity,
            "provenance": {"source": signal["source"], "raw": signal, "raw_digest": _digest(signal)}}

def normalize_signals(signals):
    queue, flagged, size = [], [], 0
    for index, signal in enumerate(_records(signals)):
        try:
            item = _normalized(signal)
        except ValueError as exc:
            # All errors are controlled diagnostics and do not include raw field values.
            flagged.append({"signal": index, "reason": str(exc)})
            continue
        size += len(_encoded(item["provenance"]["raw"]))
        if size > MAX_BYTES:
            raise ValueError("combined signal size limit exceeded")
        queue.append(item)
    return {"queue": queue, "flagged_signals": flagged}

def _verified_queue(queue):
    snapshot = _snapshot(_records(queue))
    for item in snapshot:
        if type(item) is not dict or type(item.get("provenance")) is not dict:
            raise ValueError("normalized signal requires provenance")
        if _normalized(item["provenance"].get("raw")) != item:
            raise ValueError("normalized signal does not match its raw evidence")
    return snapshot

def dedupe_to_actions(queue):
    """Collapse equal root identity and count distinct canonical evidence records."""
    actions = {}
    for item in _verified_queue(queue):
        key = (item["kind"], item["service"], item["subject"], item["environment"])
        action = actions.setdefault(key, {"action_id": "act-" + _digest(list(key))[7:],
            "kind": item["kind"], "service": item["service"], "subject": item["subject"],
            "environment": item["environment"], "severity": item["severity"], "evidence": {}})
        action["evidence"][item["provenance"]["raw_digest"]] = item["provenance"]
        if SEVERITY_RANK[item["severity"]] > SEVERITY_RANK[action["severity"]]:
            action["severity"] = item["severity"]
    result = []
    for action in actions.values():
        action["evidence"] = [value for _, value in sorted(action["evidence"].items())]
        action["occurrences"] = len(action["evidence"])
        result.append(action)
    return sorted(result, key=lambda action: action["action_id"])

def _verified_actions(actions):
    actions = _snapshot(_records(actions))
    seen = set()
    for action in actions:
        if type(action) is not dict or type(action.get("evidence")) is not list or not action["evidence"]:
            raise ValueError("action requires evidence")
        if type(action.get("occurrences")) is not int or action["occurrences"] < 1:
            raise ValueError("action occurrence count must be a positive integer")
        queue = []
        for provenance in action["evidence"]:
            if type(provenance) is not dict:
                raise ValueError("invalid action evidence")
            item = _normalized(provenance.get("raw"))
            if item["provenance"] != provenance:
                raise ValueError("action provenance does not match raw evidence")
            queue.append(item)
        expected = dedupe_to_actions(queue)
        if len(expected) != 1 or any(action.get(key) != value for key, value in expected[0].items()):
            raise ValueError("action identity, severity, count or evidence mismatch")
        if action["action_id"] in seen:
            raise ValueError("duplicate action identity")
        seen.add(action["action_id"])
    return actions

def _service_context(service_map, action):
    if type(service_map) is not dict:
        raise ValueError("service map must be an object")
    service = service_map.get(action["service"])
    if service is None:
        return {"environments": [], "owners": [], "unknowns": ["service inventory"]}
    if type(service) is not dict:
        raise ValueError("service inventory entry must be an object")
    for field in ("environments", "owners", "gaps"):
        if type(service.get(field)) is not list or any(not _label(x) for x in service[field]):
            raise ValueError("invalid service inventory field")
    environment = action["environment"]
    unknowns = []
    if environment is not None:
        scopes = service.get("scopes")
        if type(scopes) is not list:
            raise ValueError("scoped actions require scoped service inventory")
        matches = [scope for scope in scopes if type(scope) is dict and scope.get("environment") == environment]
        if len(matches) != 1:
            return {"environments": [], "owners": [], "unknowns": ["environment inventory"]}
        scope = matches[0]
        for field in ("owners", "gaps"):
            if type(scope.get(field)) is not list or any(not _label(x) for x in scope[field]):
                raise ValueError("invalid scoped inventory field")
        owners = sorted(set(scope["owners"]))
        envs = [environment]
        if scope["gaps"]:
            unknowns.append("incomplete environment inventory")
    else:
        owners = sorted(set(service["owners"]))
        envs = sorted(set(service["environments"]))
        if len(envs) > 1:
            unknowns.append("signal environment")
        if service["gaps"]:
            unknowns.append("incomplete service inventory")
    if not envs:
        unknowns.append("environment inventory")
    return {"environments": envs, "owners": owners, "unknowns": unknowns}

def prioritize(actions, service_map, effort_hints=None):
    service_map = _snapshot(service_map)
    if type(service_map) is not dict:
        raise ValueError("service map must be an object")
    effort_hints = {} if effort_hints is None else _snapshot(effort_hints)
    if type(effort_hints) is not dict or any(type(value) is not str or value not in EFFORT_RANK for value in effort_hints.values()):
        raise ValueError("effort hints must contain small, medium or large")
    actions = _verified_actions(actions)
    if set(effort_hints) - {action["action_id"] for action in actions}:
        raise ValueError("effort hint references an unknown action")
    output = []
    for action in actions:
        context = _service_context(service_map, action)
        severity = SEVERITY_RANK[action["severity"]]
        exposure = 2 if any(env.lower() in ("prod", "production") for env in context["environments"]) else 1
        recurrence = min(action["occurrences"] - 1, 2) * 0.5
        effort = effort_hints.get(action["action_id"], "medium")
        score = round(severity * 2 + (exposure + recurrence) * 1.5 - EFFORT_RANK[effort] * 0.5, 2)
        rationale = (f"severity={action['severity']} (rank {severity}) x2; "
            f"impact={exposure + recurrence} (envs={context['environments'] or 'unknown'}, "
            f"distinct evidence={action['occurrences']}) x1.5; effort={effort} (-{EFFORT_RANK[effort]*0.5})")
        output.append(dict(action, priority_score=score, effort=effort, rationale=rationale,
            score_components={"severity_rank": severity, "exposure": exposure, "recurrence": recurrence,
                              "effort_rank": EFFORT_RANK[effort]}, service_context=context))
    return sorted(output, key=lambda action: (-action["priority_score"], action["action_id"]))

def draft_recommendations(prioritized, service_map):
    how = {"vulnerability": "review the advisory, test a patched version, and schedule maintenance",
           "end-of-life": "review a migration to a supported version",
           "deprecation": "review migration away from the deprecated API",
           "dependency-update": "review the changelog and test the dependency update",
           "certificate": "review renewal and rotation before expiry",
           "capacity": "review growth, cleanup and capacity options"}
    prioritized = _verified_actions(prioritized)
    expected = prioritize(prioritized, service_map, {a["action_id"]: a.get("effort") for a in prioritized})
    if prioritized != expected:
        raise ValueError("priority data or service context does not match recomputed scores")
    recs, missing = [], []
    for action in prioritized:
        owners = action["service_context"]["owners"]
        unknowns = list(action["service_context"]["unknowns"])
        contact = owners[0] if len(owners) == 1 else None
        if not owners:
            unknowns.append("service owner")
        elif len(owners) > 1:
            unknowns.append("ambiguous service owner")
        for item in unknowns:
            missing.append({"action_id": action["action_id"], "missing": item,
                            "ask": "review inventory and identify the scope and owning team"})
        rec = {"action_id": action["action_id"],
               "what": f"{action['kind']}: {action['subject']} on {action['service']}",
               "environment": action["environment"], "why": action["rationale"], "how": how[action["kind"]],
               "whom_to_contact": contact or "UNKNOWN — see missing_context",
               "owner_candidates": owners, "priority_score": action["priority_score"],
               "score_components": action["score_components"], "state": "DRAFT",
               "missing_context": unknowns, "evidence": action["evidence"]}
        rec["recommendation_digest"] = _digest(rec)
        recs.append(rec)
    return {"schema": "mbp/recommendations/v1", "mbp_version": VERSION,
            "read_only": True, "draft_only": True, "recommendations": recs, "missing_context": missing}

def advance_state(rec, approval):
    """Record a caller-asserted human review, without authenticating an identity."""
    rec, approval = _snapshot(rec), _snapshot(approval)
    if type(rec) is not dict or type(approval) is not dict or rec.get("state") != "DRAFT":
        raise ValueError("state transition requires a draft and approval object")
    if approval.get("role") != "human":
        raise ValueError("state advances require a human approval record")
    approver = _label(approval.get("approver"))
    digest = rec.pop("recommendation_digest", None)
    if not {"action_id", "what", "why", "how", "evidence"} <= set(rec) or digest != _digest(rec):
        raise ValueError("recommendation digest missing or mismatched")
    if approval.get("recommendation_digest") != digest:
        raise ValueError("approval must bind the reviewed recommendation digest")
    rec["recommendation_digest"] = digest
    rec["state"] = "APPROVED_FOR_HUMAN_EXECUTION"
    rec["approval"] = {"approver": approver, "reviewed_digest": digest, "identity_verified": False,
                      "note": "execution remains an external, human-controlled act; identity is caller-asserted"}
    return rec
