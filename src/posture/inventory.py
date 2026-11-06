"""Source-backed coverage inventory; check identities, never historical verdicts."""
import ast
import json
from pathlib import Path
import re

from .model import COOKIE_IDS
from .privacy import sha

VERSION = 'branch1-current-coverage-1.0'
MODULES = {
    'external_rules/tls.py': ('HTTP / TLS', 'Transport Security', 'Fresh reviewed HTTP response; HTTPS-only checks require HTTPS.'),
    'external_rules/generic_rules.py': ('Headers / methods / exposure', 'HTTP Configuration', 'Fresh reviewed HTTP responses within the calculated complete native-plan budget.'),
    'external_rules/cookies.py': ('Cookies / session', 'Authentication & Session', 'Fresh response setting MoodleSession; no historical cookie is reused.'),
    'external_rules/moodle_rules.py': ('Moodle public controls', 'Access Control', 'Fresh Moodle home/login/course and reviewed endpoint responses within the shared budget.'),
    'internal.py': ('Internal read-only configuration', 'Runtime Hardening', 'Readable config.php and existing PHP collector; filesystem assertions require matching www-data UID.'),
    'intelligence.py': ('Core / patch / advisory', 'Patch & Vulnerability Intelligence', 'Fresh local version.php / collector evidence; PATCH-001 also needs an explicit compatible patch baseline.'),
}
ID = re.compile(r'[A-Z]+(?:-INT|-DEF)?-\d{3}\Z')


def controls(project, historical=()):
    """Enumerate IDs actually implemented by the accepted modules, plus legacy identities.

    AST parsing reads declarations only, so inventory cannot execute scanners or load
    historical observations. Dynamic advisory/role families are enumerated explicitly.
    """
    root = Path(project) / 'src/branch1'
    out = {}
    for relative, (family, category, prerequisite) in MODULES.items():
        file = root / relative
        if not file.is_file(): continue  # Synthetic projects may supply fixture providers.
        tree = ast.parse(file.read_text())
        ids = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
               and isinstance(n.value, str) and ID.fullmatch(n.value)}
        for original in sorted(ids):
            fid = COOKIE_IDS.get(original, original)
            cat = category
            for prefix, value in [('HDR-', 'Security Headers'), ('TLS-', 'Transport Security'),
                ('DISC-', 'Information Disclosure'), ('EXPOSURE-', 'Exposure'),
                ('AUTH-', 'Authentication & Session'), ('PRIV-', 'Privacy & Exposure'),
                ('FS-', 'Server-side Configuration'), ('SESSION-', 'Authentication & Session'),
                ('SSRF-', 'Network Egress / SSRF Defense'), ('PLUGIN-', 'Component Inventory'),
                ('MOODLE-', 'Moodle Platform'), ('TRANSPORT-', 'Transport Security')]:
                if fid.startswith(prefix): cat = value; break
            title = 'Existing Branch1 control ' + fid
            if fid.startswith('AUTH-INT-'): cat = 'Authentication & Access'
            # Exact titles/categories from literal Finding constructors, where available.
            for n in ast.walk(tree):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'Finding' and len(n.args) >= 3:
                    if all(isinstance(v, ast.Constant) and isinstance(v.value, str) for v in n.args[:3]) and n.args[0].value == original:
                        cat, title = n.args[1].value, n.args[2].value
            out[fid] = dict(finding_id=fid, category=cat, finding_type=title, family=family,
                implementation_path='src/branch1/' + relative, source_sha256=sha(file.read_bytes()),
                required_prerequisite=prerequisite, execution='RECONSIDER_EVERY_ASSESSMENT')
    advisory = root / 'advisories.json'
    if advisory.is_file():
        for a in json.loads(advisory.read_text()):
            fid = 'ADV-' + a['id']
            out[fid] = dict(finding_id=fid, category='Patch & Vulnerability Intelligence', finding_type=a['title'],
                family='Pinned advisory matching', implementation_path='src/branch1/intelligence.py',
                applicability={k:a[k] for k in ('branch','affected_min','affected_max') if k in a},
                required_prerequisite='Fresh installed branch/build matching the pinned affected range; never exploit confirmation.',
                execution='RECONSIDER_EVERY_ASSESSMENT')
    # Role names are runtime parameters. Inventory the family without inventing sessions.
    if (root / 'roles.py').is_file():
        from branch1.roles import ADMIN_ENDPOINTS
        for endpoint in sorted(ADMIN_ENDPOINTS):
            fid = 'ROLE-<verified-role>-' + endpoint
            out[fid] = dict(finding_id=fid, category='Access Control', finding_type='Cross-role content comparison: ' + endpoint,
                family='Role differential', implementation_path='src/branch1/roles.py:compare',
                required_prerequisite='Fresh verified anonymous, restricted-role and administrator sessions with reviewed capability/content markers; no current role collector is configured.',
                execution='CONDITIONAL_RUNTIME_ROLE_ID', coverage_only=True)
        from branch1.active.validators import DEFAULT_VALIDATORS
        for validator in DEFAULT_VALIDATORS:
            fid = 'VALIDATOR-' + validator.name
            out[fid] = dict(finding_id=fid, category='Active validation planning', finding_type=validator.name,
                family='Existing bounded validation', implementation_path='src/' + validator.__class__.__module__.replace('.', '/') + '.py',
                required_prerequisite='Existing planner/gate: explicit POSTURE_ENABLE_EXISTING_ACTIVE=1, reviewed B1_ACTIVE_CONTEXT, sessions where required, remaining request/time budget; no new validator or payload.',
                execution='EXISTING_PLANNER_EVERY_ASSESSMENT', coverage_only=True)
    for r in historical:
        fid = r['finding_id']
        if fid not in out:
            out[fid] = dict(finding_id=fid, category=r['category'], finding_type=r['finding_type'],
                family='Legacy identity', implementation_path='legacy/branch1/',
                required_prerequisite='Legacy finding identity has no direct fresh emitter in the accepted current port; historical verdict is never substituted. Current equivalent controls are evaluated under their own source IDs.',
                execution='COVERAGE_ONLY_UNTIL_FRESH_EMITTER_AVAILABLE')
    return [out[k] for k in sorted(out)]


def annotate(rows, inventory, native):
    """Explicit current state without changing frozen NOT_TESTED scoring semantics."""
    known = {r['finding_id']: r for r in inventory}
    prov = native.get('provenance', {})
    local = prov.get('local_collection', {})
    exhausted = ('ASSESSMENT_DEADLINE_EXCEEDED' if 'ASSESSMENT_DEADLINE_EXCEEDED' in prov.get('failure_codes', [])
                 else 'REQUEST_BUDGET_EXCEEDED' if prov.get('request_count', 0) >= prov.get('policy',{}).get('max_requests',20) else None)
    for r in rows:
        spec = known.get(r['finding_id'], {})
        # These are explicit branches in the accepted source, not failed probes.
        # Report their current applicability rather than a fictitious transport gap.
        prerequisite = None
        by_id = {v['finding_id']:v for v in rows if v['evidence_source']=='NATIVE_POSTURE'}
        parent = by_id.get('HDR-002', {})
        if r['finding_id'] in ('HDR-003','HDR-004') and parent.get('observed_value') == 'Header absent':
            prerequisite = 'Existing CSP token rule requires a non-empty CSP; the fresh response has no CSP. The missing-CSP finding remains FAIL.'
        if r['finding_id']=='COOKIE-000' and any(by_id.get(k,{}).get('operational_status') in ('PASS','FAIL','PARTIAL') for k in COOKIE_IDS.values()):
            prerequisite = 'The fresh response emitted MoodleSession attribute observations; the cookie-absence branch does not apply.'
        if r['finding_id']=='AUTH-006' and by_id.get('AUTH-001',{}).get('operational_status')=='FAIL':
            prerequisite = 'No POST login form was found in the fresh response; the action-integrity branch requires that form. The parent failure is retained.'
        if r['operational_status']=='NOT_REEVALUATED' and prerequisite:
            r.update(operational_status='NOT_APPLICABLE', check_result='NOT_APPLICABLE',
                     confirmation_status='NOT_APPLICABLE', explanation=prerequisite,
                     evidence={'applicability':prerequisite}, prerequisite_reason=None)
        if r['operational_status']=='NOT_REEVALUATED' and r['finding_id'] in ('AUTH-007','TRANSPORT-004'):
            # Both existing rules are explicitly HTTPS-only; the authorized target is HTTP.
            r.update(operational_status='NOT_APPLICABLE', check_result='NOT_APPLICABLE',
                     confirmation_status='NOT_APPLICABLE', explanation='Existing source rule is HTTPS-only; the current authorized target is HTTP.',
                     evidence={'applicability':'HTTP_TARGET; HTTPS_ONLY_RULE'}, prerequisite_reason=None)
        if r['operational_status']=='NOT_REEVALUATED' and spec.get('applicability'):
            from branch1.intelligence import base_version
            core = prov.get('internal_evidence', {}).get('core', {})
            installed, branch = base_version(core.get('version')), str(core.get('branch') or '')
            a = spec['applicability']
            upper, lower = base_version(a.get('affected_max')), base_version(a.get('affected_min'))
            if installed is not None and branch and upper is not None and ('affected_min' not in a or lower is not None):
                if branch != str(a['branch']) or installed > upper or (lower is not None and installed < lower):
                    r.update(operational_status='NOT_APPLICABLE', check_result='NOT_APPLICABLE',
                        confirmation_status='NOT_APPLICABLE', prerequisite_reason=None,
                        explanation='Fresh installed branch/build is outside this pinned advisory affected range; no exploit or latest-release claim.',
                        evidence={'fresh_core':core, 'applicability':a})
        if r['operational_status'] != 'NOT_REEVALUATED':
            r['current_state'] = r['operational_status']
            continue
        if r['category'] == 'UNMAPPED': continue
        reason = r.get('prerequisite_reason') or spec.get('required_prerequisite')
        if spec.get('family') == 'Internal read-only configuration':
            reason = local.get('reason_code') or reason
            if r['finding_id'] in ('FS-001', 'FS-002') and not local.get('reason_code'):
                reason = 'Collector/web-server UID equivalence and fresh filesystem writability evidence are required.'
            if r['finding_id'].startswith('PLUGIN-') and not local.get('reason_code'):
                reason = 'Existing plugin rule emits qualifying mismatch/nonstandard observations only; no explicit fresh negative verdict was emitted.'
        elif exhausted and spec.get('family') in ('HTTP / TLS', 'Headers / methods / exposure', 'Cookies / session', 'Moodle public controls'):
            reason = exhausted + '; ' + str(reason)
        r.update(current_state='NOT_AVAILABLE', prerequisite_reason=reason or 'Fresh provider evidence unavailable.',
                 explanation='No fresh verdict; historical result is not reused. Prerequisite: ' + str(reason or 'Fresh provider evidence unavailable.'))


def coverage(inventory, rows, native):
    by_id = {r['finding_id']: r for r in rows}
    result = []
    for spec in inventory:
        r = by_id.get(spec['finding_id'])
        result.append(dict(spec, current_state=r.get('current_state', r['operational_status']) if r else 'NOT_AVAILABLE',
                           reason=r.get('prerequisite_reason') if r else spec['required_prerequisite'],
                           assessment_scope='CURRENT_EXECUTION', historical_result_reused=False))
    return result
