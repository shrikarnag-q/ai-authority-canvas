#!/usr/bin/env python3
"""Run only fictional local actions. No actual human consent is collected."""
import json
import secrets
import tempfile
from dataclasses import asdict
from pathlib import Path
from authority_lab import AuthorityLab, Principal


def main():
    with tempfile.TemporaryDirectory() as directory:
        lab = AuthorityLab(Path(directory) / "fictional.db", secrets.token_bytes(32))
        lab.initialize_demo()
        agent, reviewer = Principal("alpha", "agent-a"), Principal("alpha", "human")
        action = lab.prepare(agent, "budget.set", "program-1", {"units": 125})
        token = lab.issue_approval(reviewer, action)
        changed = {**action, "params": {"units": 900}}
        result = {"notice": "Synthetic local simulation. Reviewer identity is scripted, not a real human approval.",
                  "preview": action,
                  "changed_action": asdict(lab.execute(agent, changed, token)),
                  "approved_action": asdict(lab.execute(agent, action, token)),
                  "replay": asdict(lab.execute(agent, action, token)),
                  "final_local_state": lab.state(agent),
                  "audit_valid": lab.verify_audit()["valid"]}
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
