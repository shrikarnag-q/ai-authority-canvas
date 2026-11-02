"""Local transaction-authorization teaching lab. Material AI assistance.

The only actions mutate fictional SQLite records. Principal objects must come
from a trusted host; this module does not authenticate people or collect consent.
No network adapters, credentials, customer systems, or real payments are used.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


IDENTIFIER = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z", re.ASCII)
ACTION_FIELDS = {"tenant", "actor", "tool", "target", "params",
                 "resource_version", "policy_version", "context_version"}
TOKEN_FIELDS = {"kind", "id", "tenant", "actor", "approver", "action_hash",
                "issued_at", "expires_at"}
MAX_TTL = 300


class Denied(ValueError):
    """A request did not meet a specified lab authorization condition."""


@dataclass(frozen=True)
class Principal:
    """Already-authenticated identity asserted by the trusted host, not a model."""
    tenant: str
    subject: str


@dataclass(frozen=True)
class Outcome:
    executed: bool
    reason: str
    resource_version: int | None = None


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Denied("duplicate_json_key")
        result[key] = value
    return result


def _identifier(value):
    return type(value) is str and IDENTIFIER.fullmatch(value) is not None


def validate_action(value: object) -> dict:
    """Validate a narrow schema and copy it before hashing or using it."""
    if type(value) is not dict:
        raise Denied("malformed_action")
    try:
        encoded = canonical(value)
        if len(encoded) > 4096:
            raise Denied("invalid_json_size")
        value = json.loads(encoded)
    except (ValueError, TypeError, RuntimeError) as exc:
        if isinstance(exc, Denied):
            raise
        raise Denied("malformed_action") from exc
    if set(value) != ACTION_FIELDS:
        raise Denied("malformed_action")
    if not all(_identifier(value[k]) for k in ("tenant", "actor", "tool", "target")):
        raise Denied("invalid_identifier")
    for key in ("resource_version", "policy_version", "context_version"):
        if type(value[key]) is not int or not 1 <= value[key] <= 2**31 - 1:
            raise Denied("invalid_version")
    params = value["params"]
    if type(params) is not dict:
        raise Denied("malformed_parameters")
    if value["tool"] == "budget.set":
        if set(params) != {"units"} or type(params["units"]) is not int:
            raise Denied("malformed_parameters")
        if not 0 <= params["units"] <= 10**9:
            raise Denied("invalid_budget")
    elif value["tool"] == "note.append":
        if set(params) != {"text"} or type(params["text"]) is not str:
            raise Denied("malformed_parameters")
        if not 1 <= len(params["text"]) <= 200:
            raise Denied("invalid_note")
    else:
        raise Denied("unknown_tool")
    return value


def parse_action(text: str) -> dict:
    """Reject duplicate fields at the JSON boundary, before creating a dict."""
    if type(text) is not str or len(text.encode("utf-8")) > 4096:
        raise Denied("invalid_json_size")
    try:
        value = json.loads(text, object_pairs_hook=_unique_object)
    except (ValueError, TypeError) as exc:
        if isinstance(exc, Denied):
            raise
        raise Denied("invalid_json") from exc
    return validate_action(value)


class AuthorityLab:
    """Single-host SQLite lab, not a deployable authorization service."""

    def __init__(self, path: str | Path, key: bytes,
                 clock: Callable[[], int] | None = None):
        if type(key) is not bytes or len(key) < 32:
            raise ValueError("Provide at least 32 bytes from a trusted key source")
        self.path = str(path)
        self._key = key
        self._audit_key = hmac.digest(key, b"authority-lab/audit/v1", "sha256")
        self._clock = clock or (lambda: int(time.time()))

    def initialize_demo(self):
        """Trusted setup only. Two synthetic tenants and two targets per tenant."""
        with self._connection() as db:
            db.executescript("""
              CREATE TABLE IF NOT EXISTS policy (
                tenant TEXT PRIMARY KEY, version INTEGER, context INTEGER,
                stopped INTEGER, limit_units INTEGER);
              CREATE TABLE IF NOT EXISTS roles (
                tenant TEXT, subject TEXT, role TEXT,
                PRIMARY KEY(tenant, subject));
              CREATE TABLE IF NOT EXISTS resources (
                tenant TEXT, target TEXT, units INTEGER, version INTEGER,
                PRIMARY KEY(tenant, target));
              CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY, tenant TEXT, body TEXT, state TEXT);
              CREATE TABLE IF NOT EXISTS notes (
                tenant TEXT, target TEXT, text TEXT);
              CREATE TABLE IF NOT EXISTS audit (
                sequence INTEGER PRIMARY KEY, body TEXT, mac TEXT);
            """)
            for tenant in ("alpha", "beta"):
                db.execute("INSERT OR IGNORE INTO policy VALUES (?,1,1,0,1000)", (tenant,))
                for subject, role in (("agent-a", "agent"), ("agent-b", "agent"),
                                      ("human", "approver"), ("admin", "admin")):
                    db.execute("INSERT OR IGNORE INTO roles VALUES (?,?,?)",
                               (tenant, subject, role))
                for target in ("program-1", "program-2"):
                    db.execute("INSERT OR IGNORE INTO resources VALUES (?,?,100,1)",
                               (tenant, target))
            db.commit()

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(self.path)
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    def _now(self):
        now = self._clock()
        if type(now) is not int or not 0 <= now < 2**62:
            raise ValueError("Trusted clock must return nonnegative integer seconds")
        return now

    def _role(self, db, principal, allowed):
        if not isinstance(principal, Principal) or not _identifier(principal.tenant) or not _identifier(principal.subject):
            raise Denied("invalid_principal")
        row = db.execute("SELECT role FROM roles WHERE tenant=? AND subject=?",
                         (principal.tenant, principal.subject)).fetchone()
        if row is None or row["role"] not in allowed:
            raise Denied("actor_not_authorized")

    def _current(self, db, action):
        policy = db.execute("SELECT * FROM policy WHERE tenant=?", (action["tenant"],)).fetchone()
        resource = db.execute("SELECT * FROM resources WHERE tenant=? AND target=?",
                              (action["tenant"], action["target"])).fetchone()
        if policy is None or resource is None:
            raise Denied("unknown_resource")
        if policy["stopped"]:
            raise Denied("stopped")
        if action["policy_version"] != policy["version"]:
            raise Denied("stale_policy")
        if action["context_version"] != policy["context"]:
            raise Denied("stale_context")
        if action["resource_version"] != resource["version"]:
            raise Denied("stale_resource")
        if action["tool"] == "budget.set" and action["params"]["units"] > policy["limit_units"]:
            raise Denied("policy_limit")
        return resource

    @staticmethod
    def action_hash(action):
        return hashlib.sha256(canonical(validate_action(action)).encode()).hexdigest()

    def prepare(self, principal, tool, target, params):
        """Build a preview from trusted current versions. It grants no approval."""
        with self._transaction() as db:
            self._role(db, principal, {"agent"})
            policy = db.execute("SELECT * FROM policy WHERE tenant=?", (principal.tenant,)).fetchone()
            resource = db.execute("SELECT * FROM resources WHERE tenant=? AND target=?",
                                  (principal.tenant, target)).fetchone()
            if resource is None or policy is None:
                raise Denied("unknown_resource")
            action = validate_action({"tenant": principal.tenant, "actor": principal.subject,
                "tool": tool, "target": target, "params": params,
                "resource_version": resource["version"], "policy_version": policy["version"],
                "context_version": policy["context"]})
            self._current(db, action)
            return action

    def _token_mac(self, payload):
        return hmac.new(self._key, canonical(payload).encode(), hashlib.sha256).hexdigest()

    def issue_approval(self, approver, action, ttl=120):
        """Trusted reviewer entry point. Host must authenticate and obtain consent."""
        action = validate_action(action)
        if type(ttl) is not int or not 1 <= ttl <= MAX_TTL:
            raise Denied("invalid_ttl")
        with self._transaction() as db:
            self._role(db, approver, {"approver"})
            if approver.tenant != action["tenant"]:
                raise Denied("tenant_mismatch")
            self._role(db, Principal(action["tenant"], action["actor"]), {"agent"})
            self._current(db, action)
            now = self._now()
            payload = {"kind": "local-approval-v1", "id": secrets.token_hex(16),
                "tenant": action["tenant"], "actor": action["actor"],
                "approver": approver.subject, "action_hash": self.action_hash(action),
                "issued_at": now, "expires_at": now + ttl}
            db.execute("INSERT INTO approvals VALUES (?,?,?,?)",
                       (payload["id"], payload["tenant"], canonical(payload), "active"))
            self._append_audit(db, approver, "issued", payload["action_hash"], payload["id"], "active")
            return {"payload": payload, "mac": self._token_mac(payload)}

    def _verify_token(self, db, principal, action, token):
        if type(token) is not dict:
            raise Denied("malformed_token")
        token = token.copy()
        if set(token) != {"payload", "mac"}:
            raise Denied("malformed_token")
        payload, mac = token["payload"], token["mac"]
        if type(payload) is not dict:
            raise Denied("malformed_token")
        payload = payload.copy()
        if set(payload) != TOKEN_FIELDS:
            raise Denied("malformed_token")
        if type(mac) is not str or re.fullmatch(r"[0-9a-f]{64}", mac, re.ASCII) is None:
            raise Denied("invalid_mac")
        if any(type(payload[k]) is not str for k in TOKEN_FIELDS - {"issued_at", "expires_at"}):
            raise Denied("malformed_token")
        if any(type(payload[k]) is not int for k in ("issued_at", "expires_at")):
            raise Denied("malformed_token")
        if len(canonical(payload)) > 2048 or not hmac.compare_digest(mac, self._token_mac(payload)):
            raise Denied("invalid_mac")
        if payload["kind"] != "local-approval-v1":
            raise Denied("wrong_token_kind")
        if payload["tenant"] != principal.tenant or payload["actor"] != principal.subject:
            raise Denied("token_identity_mismatch")
        if payload["action_hash"] != self.action_hash(action):
            raise Denied("action_mismatch")
        now = self._now()
        if now < payload["issued_at"]:
            raise Denied("not_yet_valid")
        if now >= payload["expires_at"]:
            raise Denied("expired")
        row = db.execute("SELECT * FROM approvals WHERE id=?", (payload["id"],)).fetchone()
        if row is None or row["tenant"] != principal.tenant or row["body"] != canonical(payload):
            raise Denied("unknown_approval")
        if row["state"] != "active":
            raise Denied("approval_" + row["state"])
        self._role(db, Principal(principal.tenant, payload["approver"]), {"approver"})
        return payload

    def execute(self, principal, action, token):
        """Commit one fictional mutation and consume approval in the SAME DB transaction."""
        with self._transaction() as db:
            digest = None
            try:
                self._role(db, principal, {"agent"})
                action = validate_action(action)
                digest = self.action_hash(action)
                if (action["tenant"], action["actor"]) != (principal.tenant, principal.subject):
                    raise Denied("action_identity_mismatch")
                payload = self._verify_token(db, principal, action, token)
                resource = self._current(db, action)
            except Denied as exc:
                # Invalid principals cannot safely supply log identity fields.
                identity = principal if isinstance(principal, Principal) and _identifier(principal.tenant) and _identifier(principal.subject) else Principal("unknown", "unknown")
                self._append_audit(db, identity, "denied", digest, None, str(exc))
                return Outcome(False, str(exc))
            changed = db.execute("UPDATE approvals SET state='consumed' WHERE id=? AND state='active'",
                                 (payload["id"],)).rowcount
            if changed != 1:
                raise sqlite3.IntegrityError("Approval state changed during transaction")
            if action["tool"] == "budget.set":
                db.execute("UPDATE resources SET units=?,version=version+1 WHERE tenant=? AND target=?",
                           (action["params"]["units"], principal.tenant, action["target"]))
            else:
                db.execute("INSERT INTO notes VALUES (?,?,?)",
                           (principal.tenant, action["target"], action["params"]["text"]))
                db.execute("UPDATE resources SET version=version+1 WHERE tenant=? AND target=?",
                           (principal.tenant, action["target"]))
            new_version = resource["version"] + 1
            self._append_audit(db, principal, "executed", digest, payload["id"], "committed")
            return Outcome(True, "committed", new_version)

    def revoke(self, principal, approval_id):
        with self._transaction() as db:
            self._role(db, principal, {"approver", "admin"})
            changed = db.execute("UPDATE approvals SET state='revoked' WHERE id=? AND tenant=? AND state='active'",
                                 (approval_id, principal.tenant)).rowcount
            self._append_audit(db, principal, "revoked", None, approval_id if changed else None,
                               "revoked" if changed else "no_active_approval")
            return changed == 1

    def control(self, principal, operation, value=None):
        """Trusted admin controls; policy/context changes invalidate old previews."""
        with self._transaction() as db:
            self._role(db, principal, {"admin"})
            if operation == "context":
                db.execute("UPDATE policy SET context=context+1 WHERE tenant=?", (principal.tenant,))
            elif operation == "limit" and type(value) is int and 0 <= value <= 10**9:
                db.execute("UPDATE policy SET limit_units=?,version=version+1 WHERE tenant=?", (value, principal.tenant))
            elif operation == "stop" and type(value) is bool:
                db.execute("UPDATE policy SET stopped=?,context=context+1 WHERE tenant=?", (int(value), principal.tenant))
            else:
                raise Denied("invalid_control")
            self._append_audit(db, principal, "control", None, None, operation)

    def _append_audit(self, db, principal, event, digest, approval_id, result):
        previous = db.execute("SELECT sequence,mac FROM audit ORDER BY sequence DESC LIMIT 1").fetchone()
        sequence, head = (previous["sequence"] + 1, previous["mac"]) if previous else (1, "0" * 64)
        body = canonical({"sequence": sequence, "previous": head, "time": self._now(),
            "tenant": principal.tenant, "actor": principal.subject, "event": event,
            "action_hash": digest, "approval_id": approval_id, "result": result})
        mac = hmac.new(self._audit_key, body.encode(), hashlib.sha256).hexdigest()
        db.execute("INSERT INTO audit VALUES (?,?,?)", (sequence, body, mac))

    def verify_audit(self, checkpoint=None):
        """Check the chain, optionally against an exact expected current snapshot.

        A prior checkpoint does not accept legitimate later appends: it returns
        checkpoint_mismatch. This API does not verify anchored-prefix extension.
        Retain the expected current snapshot elsewhere to detect tail deletion.
        """
        with self._connection() as db:
            rows = db.execute("SELECT sequence,body,mac FROM audit ORDER BY sequence").fetchall()
        head = "0" * 64
        try:
            for index, (sequence, body, mac) in enumerate(rows, 1):
                item = json.loads(body)
                expected = hmac.new(self._audit_key, body.encode(), hashlib.sha256).hexdigest()
                if sequence != index or item["sequence"] != index or item["previous"] != head or not hmac.compare_digest(mac, expected):
                    raise ValueError("chain_or_mac_mismatch")
                head = mac
            if checkpoint is not None and checkpoint != {"rows": len(rows), "head": head}:
                raise ValueError("checkpoint_mismatch")
        except (ValueError, TypeError, KeyError) as exc:
            return {"valid": False, "reason": str(exc), "rows": len(rows)}
        return {"valid": True, "rows": len(rows), "head": head, "anchored": checkpoint is not None}

    def state(self, principal, target="program-1"):
        with self._transaction() as db:
            self._role(db, principal, {"agent", "approver", "admin"})
            row = db.execute("SELECT units,version FROM resources WHERE tenant=? AND target=?",
                             (principal.tenant, target)).fetchone()
            return {"units": row[0], "version": row[1]} if row else None
