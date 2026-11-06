"""Reviewed current-port aliases, not fuzzy finding/title deduplication.

Legacy MVP exposed() and accepted GenericRules.exposure_checks probe these exact
four origin paths. Their ID migration must not create additional missing units.
EXPOSURE-001 was also used for a different legacy directory-listing check, so an
ID alone is insufficient: require the actual current emitter observation.
"""

EXPOSURE_ALIASES={
    'EXPOSURE-SERVER-STATUS':('EXPOSURE-001','Exposed Apache server-status','/server-status'),
    'EXPOSURE-PHPINFO-PHP':('EXPOSURE-002','Exposed PHP diagnostic page','/phpinfo.php'),
    'EXPOSURE--GIT-HEAD':('EXPOSURE-003','Exposed Git metadata','/.git/HEAD'),
    'EXPOSURE--ENV':('EXPOSURE-004','Exposed Environment file','/.env'),
}


def current_exposure_aliases(rows,expected):
    """Only complete current observations can resolve unobserved legacy aliases.

    No old verdict is reused, no observed legacy weakness is suppressed, and no
    partial/error/stale observation is promoted to a PASS. Legacy replay remains
    unchanged. HTTP non-200 PASS proves both old/new 200-gated predicates false;
    a confirmed matched exposure retains its existing supported hazard.
    """
    aliases={};proof=[]
    for old,(new,title,path) in EXPOSURE_ALIASES.items():
        if expected.get(new,{}).get('dimension')!='D3':continue
        candidates=[]
        for row in rows:
            e=row.get('evidence')
            observation=e.get('observation') if isinstance(e,dict) else None
            if not isinstance(observation,dict):continue
            status=row.get('current_state') or row.get('operational_status') or row.get('check_result')
            aid=row.get('assessment_id')
            if (row.get('finding_id')!=new or not aid or row.get('evidence_source')!='NATIVE_POSTURE'
                    or row.get('category')!='Exposure' or row.get('finding_type')!=title
                    or (row.get('provenance') or {}).get('assessment_id')!=aid
                    or observation.get('finding_id')!=new or observation.get('indicator')!=title
                    or observation.get('status')!=status):continue
            observed=observation.get('observed','')
            complete=(status=='PASS' and any(observed.startswith('HTTP '+str(code)+';') for code in (301,302,303,307,308,400,401,403,404,405,410)))
            complete |= status=='FAIL' and row.get('confirmation_status')=='CONFIRMED' and observed=='HTTP 200; marker=matched'
            if not complete:continue
            legacy=[r for r in rows if r.get('finding_id')==old]
            if any(r.get('assessment_id')!=aid or r.get('affected_asset')!=row.get('affected_asset')
                   or (r.get('current_state') or r.get('operational_status') or r.get('check_result')) not in ('NOT_AVAILABLE','NOT_REEVALUATED','NOT_TESTED')
                   or r.get('confirmation_status')!='NOT_TESTED'
                   or not (r.get('prerequisite_reason') or '').startswith('Legacy finding identity has no direct fresh emitter') for r in legacy):continue
            candidates.append(row)
        if not candidates:continue
        # Never resolve an ambiguous cross-assessment/target alias.
        if len({(r['assessment_id'],r.get('affected_asset')) for r in candidates})!=1:continue
        aliases[old]=new
        proof.append({'legacy_control_id':old,'canonical_control_id':new,'endpoint_path':path,
            'assessment_id':candidates[0]['assessment_id'],
            'current_evidence_ids':sorted({r['evidence_id'] for r in candidates}),
            'reason':'Explicit emitter identity migration; one current root, no additional missing unit; raw evidence retained'})
    return aliases,proof
