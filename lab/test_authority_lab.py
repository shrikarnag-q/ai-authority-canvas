"""Author-defined synthetic adversarial checks; not independent validation."""
import copy
import json
import multiprocessing
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from authority_lab import AuthorityLab, Denied, Principal, canonical, parse_action

FIXTURE_TIME = 1793620800
TEST_KEY = b"synthetic-test-key-not-for-deployment-000000"


def crash_before_audit(path, action, token):
    lab = AuthorityLab(path, TEST_KEY, lambda: FIXTURE_TIME)
    # The local mutation has run, but neither it nor token use has committed.
    lab._append_audit = lambda *args: os._exit(73)
    lab.execute(Principal("alpha", "agent-a"), action, token)


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "fictional.db"
        self.now = FIXTURE_TIME
        self.lab = AuthorityLab(self.path, TEST_KEY, lambda: self.now)
        self.lab.initialize_demo()
        self.agent = Principal("alpha", "agent-a")
        self.human = Principal("alpha", "human")
        self.admin = Principal("alpha", "admin")
        self.action = self.lab.prepare(self.agent, "budget.set", "program-1", {"units": 125})
        self.token = self.lab.issue_approval(self.human, self.action)

    def tearDown(self):
        self.directory.cleanup()

    def execute(self, action=None, token=None, principal=None):
        return self.lab.execute(principal or self.agent,
                                self.action if action is None else action,
                                self.token if token is None else token)

    def unchanged(self):
        self.assertEqual(self.lab.state(self.agent), {"units": 100, "version": 1})

    def sql(self, statement, args=()):
        with sqlite3.connect(self.path) as db:
            return db.execute(statement, args).fetchall()

    def test_exact_approved_budget_commits(self):
        self.assertTrue(self.execute().executed)
        self.assertEqual(self.lab.state(self.agent), {"units": 125, "version": 2})

    def test_approved_note_commits_once(self):
        action = self.lab.prepare(self.agent, "note.append", "program-1", {"text": "Fictional note"})
        token = self.lab.issue_approval(self.human, action)
        self.assertTrue(self.execute(action, token).executed)
        self.assertFalse(self.execute(action, token).executed)
        self.assertEqual(self.sql("SELECT count(*) FROM notes")[0][0], 1)

    def test_missing_token_does_not_execute(self):
        self.assertFalse(self.lab.execute(self.agent, self.action, None).executed)
        self.unchanged()

    def test_approved_flag_does_not_grant_authority(self):
        action = {**self.action, "approved": True}
        self.assertEqual(self.execute(action).reason, "malformed_action")
        self.unchanged()

    def test_changed_parameters_rejected_without_burning_approval(self):
        action = {**self.action, "params": {"units": 900}}
        self.assertEqual(self.execute(action).reason, "action_mismatch")
        self.unchanged()
        self.assertTrue(self.execute().executed)

    def test_changed_target_rejected(self):
        self.assertFalse(self.execute({**self.action, "target": "program-2"}).executed)
        self.assertEqual(self.lab.state(self.agent, "program-2")["units"], 100)
        self.unchanged()

    def test_changed_tool_rejected(self):
        action = {**self.action, "tool": "note.append", "params": {"text": "Fictional"}}
        self.assertEqual(self.execute(action).reason, "action_mismatch")
        self.assertEqual(self.sql("SELECT count(*) FROM notes")[0][0], 0)

    def test_changed_actor_rejected(self):
        self.assertEqual(self.execute({**self.action, "actor": "agent-b"}).reason,
                         "action_identity_mismatch")
        self.unchanged()

    def test_other_agent_cannot_use_bearer_token(self):
        action = {**self.action, "actor": "agent-b"}
        self.assertFalse(self.execute(action, principal=Principal("alpha", "agent-b")).executed)
        self.unchanged()

    def test_other_tenant_cannot_use_token(self):
        action = {**self.action, "tenant": "beta"}
        beta = Principal("beta", "agent-a")
        self.assertFalse(self.execute(action, principal=beta).executed)
        self.assertEqual(self.lab.state(beta)["units"], 100)
        self.unchanged()

    def test_other_tenant_cannot_issue_approval(self):
        with self.assertRaises(Denied):
            self.lab.issue_approval(Principal("beta", "human"), self.action)

    def test_agent_cannot_approve(self):
        with self.assertRaises(Denied):
            self.lab.issue_approval(self.agent, self.action)

    def test_approver_cannot_execute_as_agent(self):
        self.assertFalse(self.execute(principal=self.human).executed)
        self.unchanged()

    def test_unknown_principal_rejected(self):
        self.assertFalse(self.execute(principal=Principal("alpha", "stranger")).executed)
        self.unchanged()

    def test_revoked_executor_role_rejected(self):
        self.sql("DELETE FROM roles WHERE tenant='alpha' AND subject='agent-a'")
        self.assertEqual(self.execute().reason, "actor_not_authorized")
        self.assertEqual(self.lab.state(self.admin)["units"], 100)

    def test_revoked_approver_role_invalidates_token(self):
        self.sql("DELETE FROM roles WHERE tenant='alpha' AND subject='human'")
        self.assertEqual(self.execute().reason, "actor_not_authorized")
        self.unchanged()

    def test_token_mac_tampering_rejected(self):
        token = copy.deepcopy(self.token)
        token["payload"]["expires_at"] += 100
        self.assertEqual(self.execute(token=token).reason, "invalid_mac")
        self.unchanged()

    def test_non_ascii_mac_rejected_safely(self):
        token = {**self.token, "mac": "é" * 64}
        self.assertEqual(self.execute(token=token).reason, "invalid_mac")
        self.unchanged()

    def test_unknown_approval_even_with_valid_mac_rejected(self):
        self.sql("DELETE FROM approvals")
        self.assertEqual(self.execute().reason, "unknown_approval")
        self.unchanged()

    def test_expired_token_rejected_at_exact_boundary(self):
        self.now += 120
        self.assertEqual(self.execute().reason, "expired")
        self.unchanged()

    def test_clock_before_issuance_rejected(self):
        self.now -= 1
        self.assertEqual(self.execute().reason, "not_yet_valid")
        self.unchanged()

    def test_invalid_ttl_rejected(self):
        for ttl in (0, -1, 301, True, 1.5, "120"):
            with self.assertRaises(Denied):
                self.lab.issue_approval(self.human, self.action, ttl)

    def test_revoked_approval_rejected(self):
        self.assertTrue(self.lab.revoke(self.human, self.token["payload"]["id"]))
        self.assertEqual(self.execute().reason, "approval_revoked")
        self.unchanged()

    def test_other_tenant_cannot_revoke_approval(self):
        self.assertFalse(self.lab.revoke(Principal("beta", "human"), self.token["payload"]["id"]))
        self.assertTrue(self.execute().executed)

    def test_policy_change_invalidates_approval(self):
        self.lab.control(self.admin, "limit", 900)
        self.assertEqual(self.execute().reason, "stale_policy")
        self.unchanged()

    def test_context_change_invalidates_approval(self):
        self.lab.control(self.admin, "context")
        self.assertEqual(self.execute().reason, "stale_context")
        self.unchanged()

    def test_stop_and_resume_require_new_approval(self):
        self.lab.control(self.admin, "stop", True)
        self.assertEqual(self.execute().reason, "stopped")
        self.lab.control(self.admin, "stop", False)
        self.assertEqual(self.execute().reason, "stale_context")
        self.unchanged()

    def test_agent_cannot_change_trusted_policy(self):
        with self.assertRaises(Denied):
            self.lab.control(self.agent, "limit", 10**9)

    def test_policy_limit_blocks_issuance(self):
        action = {**self.action, "params": {"units": 1001}}
        with self.assertRaises(Denied):
            self.lab.issue_approval(self.human, action)
        self.unchanged()

    def test_replay_rejected(self):
        self.assertTrue(self.execute().executed)
        self.assertEqual(self.execute().reason, "approval_consumed")
        self.assertEqual(self.lab.state(self.agent)["version"], 2)

    def test_separate_approval_with_stale_resource_rejected(self):
        second = self.lab.issue_approval(self.human, self.action)
        self.assertTrue(self.execute().executed)
        self.assertEqual(self.execute(token=second).reason, "stale_resource")

    def test_sixteen_concurrent_uses_commit_exactly_one_local_mutation(self):
        barrier = threading.Barrier(16)
        def attempt(_):
            broker = AuthorityLab(self.path, TEST_KEY, lambda: FIXTURE_TIME)
            barrier.wait(timeout=10)
            return broker.execute(self.agent, self.action, self.token)
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(attempt, range(16)))
        self.assertEqual(sum(r.executed for r in results), 1)
        self.assertEqual(self.lab.state(self.agent), {"units": 125, "version": 2})
        self.assertTrue(self.lab.verify_audit()["valid"])

    def test_revocation_execution_race_has_serial_outcome(self):
        barrier = threading.Barrier(2)
        def consume():
            barrier.wait(timeout=10)
            return self.execute()
        def revoke():
            barrier.wait(timeout=10)
            return self.lab.revoke(self.human, self.token["payload"]["id"])
        with ThreadPoolExecutor(max_workers=2) as pool:
            execution, revocation = pool.submit(consume), pool.submit(revoke)
            outcome, revoked = execution.result(), revocation.result()
        self.assertNotEqual(outcome.executed, revoked)
        self.assertEqual(self.lab.state(self.agent)["units"], 125 if outcome.executed else 100)

    def test_audit_failure_rolls_back_mutation_and_consumption(self):
        checkpoint = self.lab.verify_audit()
        with patch.object(self.lab, "_append_audit", side_effect=sqlite3.OperationalError("synthetic audit failure")):
            with self.assertRaises(sqlite3.OperationalError):
                self.execute()
        self.unchanged()
        self.assertTrue(self.lab.verify_audit({"rows": checkpoint["rows"], "head": checkpoint["head"]})["valid"])
        self.assertTrue(self.execute().executed)

    def test_abrupt_process_exit_before_commit_rolls_back(self):
        context = multiprocessing.get_context("spawn")
        child = context.Process(target=crash_before_audit, args=(str(self.path), self.action, self.token))
        child.start()
        child.join(timeout=10)
        if child.is_alive():
            child.terminate()
            child.join(timeout=5)
            self.fail("Synthetic crash worker did not finish")
        self.assertEqual(child.exitcode, 73)
        self.unchanged()
        self.assertTrue(self.execute().executed)

    def test_duplicate_json_parameter_rejected(self):
        text = canonical(self.action).replace('"units":125', '"units":125,"units":126')
        with self.assertRaisesRegex(Denied, "duplicate_json_key"):
            parse_action(text)

    def test_reordered_keys_have_same_binding(self):
        reordered = dict(reversed(list(self.action.items())))
        self.assertEqual(self.lab.action_hash(reordered), self.lab.action_hash(self.action))
        self.assertTrue(self.execute(reordered).executed)

    def test_preview_detaches_mutable_parameter_input(self):
        params = {"units": 125}
        action = self.lab.prepare(self.agent, "budget.set", "program-1", params)
        params["units"] = 900
        self.assertEqual(action["params"]["units"], 125)

    def test_noninteger_and_extra_parameters_rejected(self):
        for params in ({"units": True}, {"units": 125.0}, {"units": float("nan")}, {"units": "125"},
                       {"units": -1}, {"units": 125, "limit": 10000}):
            self.assertFalse(self.execute({**self.action, "params": params}).executed)
        self.unchanged()

    def test_unknown_tool_and_invalid_identifiers_rejected(self):
        for key, value in (("tool", "shell.run"), ("target", "../program-1"),
                           ("tenant", "αlpha"), ("actor", "AGENT-A")):
            self.assertFalse(self.execute({**self.action, key: value}).executed)
        self.unchanged()

    def test_malformed_versions_rejected(self):
        for value in (True, 1.0, "1", 0, -1, 2**40):
            self.assertFalse(self.execute({**self.action, "policy_version": value}).executed)
        self.unchanged()

    def test_unknown_resource_cannot_be_prepared(self):
        with self.assertRaises(Denied):
            self.lab.prepare(self.agent, "budget.set", "missing", {"units": 1})

    def test_audit_detects_modified_record(self):
        self.assertTrue(self.execute().executed)
        self.sql("UPDATE audit SET body=replace(body,'committed','changed') WHERE sequence=2")
        self.assertFalse(self.lab.verify_audit()["valid"])

    def test_tail_deletion_requires_external_checkpoint(self):
        self.assertTrue(self.execute().executed)
        record = self.lab.verify_audit()
        checkpoint = {"rows": record["rows"], "head": record["head"]}
        self.sql("DELETE FROM audit WHERE sequence=2")
        self.assertTrue(self.lab.verify_audit()["valid"])
        self.assertFalse(self.lab.verify_audit(checkpoint)["valid"])

    def test_audit_does_not_copy_note_contents_or_token_mac(self):
        text = "fictional-payload-not-for-the-log"
        action = self.lab.prepare(self.agent, "note.append", "program-1", {"text": text})
        token = self.lab.issue_approval(self.human, action)
        self.assertTrue(self.execute(action, token).executed)
        audit = canonical(self.sql("SELECT body FROM audit"))
        self.assertNotIn(text, audit)
        self.assertNotIn(token["mac"], audit)


if __name__ == "__main__":
    unittest.main()
