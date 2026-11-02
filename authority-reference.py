#!/usr/bin/env python3
"""AI-assisted reference exercise for the AI authority canvas, version 1.0.

Synthetic decision inputs only. This is not an authorization service. Identity,
approval authenticity, tamper resistance, and real execution are not implemented.
Never connect this demonstrator directly to a production action or data source.
"""
import copy
import datetime as dt
import json
import sys
from pathlib import Path

NOW = dt.datetime(2026, 11, 2, 12, 0, tzinfo=dt.timezone.utc)
SCOPES = {'read', 'draft', 'internal', 'external'}
DATA_CLASSES = {'public', 'internal', 'sensitive'}
IMPACTS = {'low', 'significant', 'high'}

def decision(request, approval=None, now=NOW):
    """Return a simulated decision, never execute the request."""
    def result(state, reason):
        return {'decision': state, 'reason': reason}
    if request.get('scope') not in SCOPES or request.get('data') not in DATA_CLASSES or request.get('impact') not in IMPACTS:
        return result('blocked', 'Unknown scope, data class, or impact')
    if not all(request.get(k) for k in ['action_id', 'owner', 'context_version', 'policy_version']):
        return result('blocked', 'Required action, owner, or version context is missing')
    if request.get('identity_bound') is not True:
        return result('blocked', 'No simulated identity binding')
    if request.get('stop_requested') is True:
        return result('blocked', 'A stop condition has been raised')
    if request['data'] == 'sensitive' or request['impact'] == 'high':
        return result('blocked', 'Outside the supported demonstrator scope; specialist review required')
    if not all(request.get('evidence', {}).get(k) for k in ['source_timestamp', 'rationale']):
        return result('blocked', 'Required evidence is missing')
    needs_approval = request['scope'] in {'internal', 'external'} or request['impact'] == 'significant'
    if not needs_approval:
        return result('permitted', 'Read or draft work within the declared low-impact scope')
    if not approval:
        return result('approval_required', 'A named human must approve this action')
    if approval.get('decision') != 'approve':
        return result('blocked', 'Human approval was not granted')
    if approval.get('approver') != request['owner']:
        return result('approval_required', 'The declared owner must review the action')
    for field in ['action_id', 'context_version', 'policy_version']:
        if approval.get(field) != request.get(field):
            return result('approval_required', 'Approval does not match the action and current versions')
    try:
        expires = dt.datetime.fromisoformat(approval.get('expires_at', '').replace('Z', '+00:00'))
        if expires.tzinfo is None or expires <= now:
            return result('approval_required', 'Approval is expired or has no timezone')
    except (ValueError, TypeError):
        return result('approval_required', 'Approval has no valid expiration')
    return result('permitted', 'Matching simulated approval is current')

def evaluate(cases):
    results=[]
    for case in cases:
        output=decision(copy.deepcopy(case['request']),copy.deepcopy(case.get('approval')))
        results.append({'case':case['id'],'expected':case['expected'],'actual':output['decision'],'reason':output['reason'],'matched':case['expected']==output['decision']})
    return {'version':'1.0','fixture_time':NOW.isoformat(),'scope':'Synthetic decision scenarios only; matching expectations does not establish production security, performance, novelty, or real-world impact.','cases':len(results),'matched':sum(r['matched'] for r in results),'results':results}

if __name__ == '__main__':
    path=Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).with_name('authority-scenarios.json')
    cases=json.loads(path.read_text())['scenarios']
    report=evaluate(cases)
    print(json.dumps(report,indent=2))
    sys.exit(0 if report['matched']==report['cases'] else 1)
