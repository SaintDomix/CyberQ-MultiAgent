"""Offline browser-protocol plan only. No network/credential/capture execution."""
import hashlib
import random

PROFILES = (
    ('P01','successful_login_dashboard','Fresh authorized login; dashboard load; ordinary navigation; logout.'),
    ('P02','one_error_then_success','Exactly one deliberately wrong password for a designated test account, then authorized successful login; stop on lockout warning.'),
    ('P03','course_navigation','Browse an actually accessible course; switch courses only if two are available; no enrollment or edits.'),
    ('P04','profile_quiz_read_only','Open own profile and an available quiz information page; never start/submit an attempt, edit profile or grade.'),
    ('P05','cold_cache_ajax_assets','Fresh browser cache; dashboard and course pages; let automatic asset/AJAX loading finish; no artificial parallel flood.'),
    ('P06','warm_cache_rapid_normal','Warm-cache browser; normal dashboard/course/back navigation, then slow pauses; human navigation only.'),
)


def plan(seed=42):
    rng=random.Random(seed);runs=[]
    # Coverage quota, not a power calculation: four fresh sessions per profile.
    # Role distribution alternates; roles and course availability need approval
    # and preflight documentation, never inferred from Apache logs.
    for code,name,instructions in PROFILES:
        for repeat in range(4):
            partition=('TRAIN','TRAIN','VALIDATION','TEST')[repeat]
            role=('student','administrator','student','administrator')[repeat]
            if code in ('P02','P04') and role=='administrator':role='student'
            runs.append({'run_id':f'M5B-{code}-{repeat+1:02d}','profile':name,'seed':rng.randrange(2**32),
                'partition_reserved_before_capture':partition,'role_requested':role,
                'duration_seconds':rng.choice((120,150,180)),
                'instructions':instructions,'label_proposal':'BENIGN_PENDING_PROTOCOL_REVIEW',
                'preconditions':'Authorized test identity; installed/enabled resource confirmed; no state-changing actions except own login/logout.',
                'stop':'Unexpected warning, foreign traffic, state mutation or resource unavailable: preserve run as excluded/unadjudicated; never invent action'})
    rng.shuffle(runs)
    external=[{'session_id':f'M5E-{i:02d}','use':'EXTERNAL_BLIND_REPLICATION',
        'minimum_seconds':180,'operator':'Separate approved browser session; preferably another authorized user/browser/day',
        'review':'Independent action diary/audit review; no tuning after inspection'} for i in range(1,7)]
    return {'version':'m5-browser-capture-proposal-1.0','seed':seed,'runs':runs,
        'proposed_new_benign_runs':24,'partition_counts':{'TRAIN':12,'VALIDATION':6,'TEST':6},
        'external_replication_sessions':external,'total_browser_minutes':sum(r['duration_seconds'] for r in runs)/60,
        'validation_resolution_goal':'At least 100 observed benign VALIDATION windows before studying a 1% empirical FPR; add predeclared replicates if actual nonempty-window count is lower.',
        'counts_rationale':'Scenario/role coverage proposal, not statistically powered sample size or proof of population FPR.',
        'network_requests_made':0,'credentials_required_by_plan':False}
