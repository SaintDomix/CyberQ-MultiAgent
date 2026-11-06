# External passive posture providers

ZAP belongs to Branch 1: it supplies deterministic external web-security
observations. Behavioral v2 remains the AI component. Passive findings do not
prove exploitability or replace penetration testing.

`ExternalScannerProvider` defines availability/health, supported modes, target
validation, start/status, collection and provenance. `NativePostureProvider`
wraps unchanged native rule functions; `ZapPassiveProvider` controls only a
dedicated owned ephemeral loopback daemon with a fresh unnamed session per assessment. The API/frontend consume canonical application
findings and never depend on ZAP report structure.

## Closed policy

This is the unchanged ZAP-specific profile. The current native provider reuses
the broader accepted Branch1 read-only endpoint/method checks separately; see
`DYNAMIC_POSTURE_ASSESSMENT.md`. Native scope expansion never changes ZAP scope.

Only `moodle-local`, authorized `http://192.168.226.132/moodle/` is accepted.
Policy: PASSIVE_BASELINE, active_scan=false, off-origin deny, no state-changing
actions, depth zero, <=20 attempted requests/provider, <=60 seconds collection,
2 MB/HTTP response, 5 MB/API response, <=500 alerts. Failed HTTP sends consume
budget. Control calls have bounded timeouts; queue waiting uses the collection
deadline. No environment proxies/netrc, arbitrary URLs, shell commands, POST
forms, TRACE, uploads, fuzzing or attack payloads are accepted.

Coverage uses a fixed reviewed page list (home, login, my, course, admin) rather
than a spider that could submit forms or visit mutation links. Native redirects
are individually validated against that exact page list. ZAP navigation never
follows redirects. No security-report page is requested. Same-origin paths
outside the Moodle mount and unreviewed paths are blocked.

ZAP runs in **safe** mode. Its passive scanner observes ordinary proxied traffic;
this adapter intentionally does not use `sendRequest`, because the official API
states that custom manual requests are disallowed in Safe mode. The only control
actions are `newSession()` (unnamed, owned runtime only), `setMode(safe)` and
passive `setEnabled(true)`. Read-only active/spider checks reject unsafe/shared
runtimes; a new owned session must verify empty before collection. There is no active scanner or
spider action route. The passive queue must finish before findings are accepted.

## Typed history integrity

The site-tree URL list is not a list of transmitted HTTP requests. ZAP 2.17.0
[`SiteMap.createReference`](https://github.com/zaproxy/zaproxy/blob/v2.17.0/zap/src/main/java/org/parosproxy/paros/model/SiteMap.java#L638)
creates GET ancestor placeholders with `HistoryReference.TYPE_TEMPORARY = 0`.
They have status 0, sent timestamp 0, RTT 0 and empty request/response bodies.
[`CoreAPI`](https://github.com/zaproxy/zaproxy/blob/v2.17.0/zap/src/main/java/org/zaproxy/zap/extension/api/CoreAPI.java#L1630)
includes tree ancestors in `urls` and temporary records in `messages` and
`numberOfMessages`. Therefore the history count need not equal provider requests.

The retained failed run `posture-20261016T030958Z-22fe09a7297a` was inspected
read-only through the existing loopback control tunnel. It contained:

| History IDs | Classification | Paths |
| --- | --- | --- |
| 1, 4, 6, 8, 10 | Type 1, real proxy GETs | `/moodle/`, `/moodle/login/index.php`, `/moodle/my/`, `/moodle/course/`, `/moodle/admin/` |
| 2, 3, 5, 7, 9, 11 | Type 0, unsent site-tree ancestors | empty host-root path, `/moodle`, `/moodle/login`, `/moodle/my`, `/moodle/course`, `/moodle/admin` |

The five responses were 200/200/303/200/303. All 29 alert URLs were reviewed
target URLs. No loopback control-plane records appeared in these 11 messages.
The old post-collection `any(not scoped(url) or path not in reviewed_paths)`
predicate on `core/view/urls` rejected the ancestors, starting at the host-root
entry. The original failed snapshot is retained unchanged; it is not relabelled.
A read-only replay of the corrected validator against that retained history and
the preserved provider transcript passed with 11 total, 5 target, 6 internal,
0 control-plane and 0 unexpected messages. This did not send Moodle requests,
execute scanner actions or create a replacement assessment. A fresh acceptance
still requires the clean operator run below.

The provider now reads bounded, typed history before collection and after the
passive queue drains. At most 100 messages (101 requested to detect overflow)
and the existing 5 MB API response cap are allowed. An incomplete/malformed
history fails closed. `numberOfMessages` is checked for completeness, not equated
with the five application requests. Counts may grow by already-issued control
queries between the count and history reads.

Classification is explicit:

- **TARGET**: type 1, GET, empty request body, matching Host/URI and provider
  User-Agent, strictly reviewed Moodle URL, and matching URL/method/status
  multiplicities in the current provider transcript. Missing/extra requests fail.
  A reviewed request receiving 303 remains valid; no redirect is followed and
  additional redirect-derived navigation has no exemption.
- **CONTROL_PLANE**: type 1 GET with empty request body, successful response and
  exact configured loopback origin, API path and decoded query arguments of a
  call actually issued by this assessment. Recorded multiplicity cannot exceed
  issued calls. Arbitrary loopback URLs/actions do not qualify. API keys remain
  header-only and never enter diagnostics.
- **INTERNAL_SITE_TREE_ANCESTOR**: type 0 with all unsent metadata above, and an
  exact ancestor URL derived from this assessment's reviewed target requests.
  A real request to the same ancestor/root URL still fails. No arbitrary
  temporary record or status-0 request is ignored.
- **UNEXPECTED**: everything else fails with `SCOPE_INTEGRITY_FAILURE`.

After automatic unnamed-session creation, preflight uses an empty target transcript: any pre-existing target traffic or
ancestor evidence fails; the provider never resets a shared daemon. Active/spider
jobs and mode changes remain fatal. Control/internal alerts are excluded before
canonical conversion; only proven target URLs can produce posture evidence.
The canonical mapping and CQI policy are unchanged.

`zap.json.scope_integrity` contains the decision/phase/version, total, target,
control-plane, internal and unexpected counts, bounded sanitized unexpected
origin/path lists, failure reasons and structural message classifications.
Raw headers, bodies, cookies, credentials, query values and alert payloads are
never exported. Unknown paths/hostnames are withheld because they may contain
tokens. `urls_observed` counts only validated target URLs, while
`messages_observed` retains the complete classified history count. Neither
control traffic nor placeholders enter findings or CQI.

Official references: [API](https://www.zaproxy.org/docs/api/),
[modes](https://www.zaproxy.org/docs/desktop/start/features/modes/),
[cookie Secure rule](https://www.zaproxy.org/docs/alerts/10011/).

## Runtime setup — operator only

No installation was performed. Prefer an existing Kali ZAP installation:

```bash
# On Kali: inspect first. Install only if absent and explicitly desired.
command -v zaproxy
# Operator/administrator optional installation, never executed by this project:
# sudo apt install zaproxy

# Dedicated volatile home; no user browser or historical ZAP session is adopted.
zap_home="$(mktemp -d /dev/shm/dissertation-zap.XXXXXXXX)"
mkdir "$zap_home/tmp"
JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=$zap_home/tmp" zaproxy \
  -daemon -silent -host 127.0.0.1 -port 8081 -dir "$zap_home" \
  -config view.mode=safe -config api.disablekey=true
```

The no-key daemon is permitted **only** on loopback on the authorized local lab
host, with no untrusted local users. Never bind it publicly. Its home/logs/session
storage must remain volatile because ZAP internally sees public session cookies.
No ZAP session/HAR containing cookies is exported to the repository. This is an
operator deployment prerequisite, not a claim that disk-backed/shared daemons
are safe. Stop the owned daemon when finished. Subsequent assessments automatically create
a fresh unnamed session; a manual restart per assessment is no longer required.
The adapter never adopts or resets a shared session; see the current lifecycle
in DYNAMIC_POSTURE_ASSESSMENT.md.

If ZAP runs on Kali, open a loopback-only tunnel from Ubuntu (replace the account
placeholder with the authorized SSH account; no password appears in arguments):

```bash
ssh -N -L 127.0.0.1:8081:127.0.0.1:8081 <authorized-kali-user>@192.168.226.129
```

In the Ubuntu terminal that launches the backend/CLI:

```bash
cd /home/saintdomix/dissertation_model
export POSTURE_ZAP_OWNED_EPHEMERAL=1
export POSTURE_ZAP_API_ORIGIN=http://127.0.0.1:8081
# Non-secret marker for the explicitly loopback/no-key daemon above:
export POSTURE_ZAP_API_KEY=LOOPBACK_EPHEMERAL_NO_KEY
.venv/bin/python -B scripts/run_posture.py status
.venv/bin/python -B scripts/run_posture.py assess --authorized
```

An already securely configured API may instead receive its actual API key from
hidden input/environment. It is sent only in `X-ZAP-API-Key`, never URL parameters
or persisted metadata. Do not paste secrets into source/chat. Without this
operator-owned volatile configuration, ZAP stays UNAVAILABLE; native still runs.
ZAP 2.17.0 reachability, the five proxied GETs and passive queue completion have
now been observed in the retained failed run. Acceptance of the corrected
history accounting remains pending the single clean operator run below.

### One clean acceptance after the history fix

1. On Kali, stop only the existing dedicated daemon in its owning terminal
   (Ctrl+C), preserving any existing research files. Restart it with a **new**
   volatile home using the safe/silent command above and the same existing API
   security configuration. Keep/reopen the loopback-only Ubuntu SSH tunnel.
   Do not attach a browser, proxy other tools, or run a spider/active scanner.
2. In the Ubuntu operator terminal, set the three `POSTURE_ZAP_*` variables
   above (retain the existing environment API key for a keyed daemon). Execute
   exactly one assessment; it creates a new unique runtime snapshot:

   ```bash
   cd /home/saintdomix/dissertation_model
   .venv/bin/python -B scripts/run_posture.py assess --authorized > /tmp/posture-zap-acceptance.json
   ```

3. Independently check the new snapshot and all its exported artifact hashes:

   ```bash
   .venv/bin/python -B - <<'PY'
   import hashlib, json, re
   from pathlib import Path
   receipt = json.loads(Path('/tmp/posture-zap-acceptance.json').read_text())
   aid = receipt['assessment_id']
   assert re.fullmatch(r'posture-\d{8}T\d{6}Z-[0-9a-f]{12}', aid)
   root = Path('runtime/posture') / aid
   manifest = json.loads((root / 'artifact_manifest.json').read_text())
   for name, expected in manifest['files'].items():
       assert Path(name).name == name
       p = root / name
       assert not p.is_symlink() and p.stat().st_size == expected['bytes']
       assert hashlib.sha256(p.read_bytes()).hexdigest() == expected['sha256']
   zap = json.loads((root / 'zap.json').read_text())
   scope = zap['scope_integrity']
   assert zap['status'] == 'COMPLETE' and scope['result'] == 'PASS'
   assert zap['passive_queue_complete'] and scope['unexpected_messages'] == 0
   assert zap['provenance']['request_count'] == scope['target_messages'] == 5
   assert zap['urls_observed'] == 5
   assert zap['provenance']['policy']['mode'] == 'PASSIVE_BASELINE'
   assert zap['provenance']['policy']['active_scan'] is False
   print(json.dumps({'assessment_id': aid, 'zap_status': zap['status'],
       'scope_integrity': scope, 'artifact_hashes': 'VERIFIED'}, indent=2))
   PY
   ```

Overall job PARTIAL can still reflect unsupported native checks or unmapped
passive rules; that does not substitute for checking ZAP COMPLETE and scope PASS.
Stop the owned daemon after this one acceptance. Do not reuse the failed history
or export raw ZAP session/HAR data.

## Mapping, privacy and evidence

Risk 0/Informational → INFO, 1/Low → LOW, 2/Medium → MEDIUM, 3/High → HIGH.
Confidence is preserved as its native ordinal label/code, never probability.
False-positive confidence → DISMISSED/FALSE_POSITIVE. Other mapped alerts →
FAIL/NOT_CONFIRMED (passive potential weakness, not exploitation confirmation).
Unknown rules → UNMAPPED/NOT_REEVALUATED, excluded from score and reported in
coverage; unknown/malformed risk/confidence fails the provider closed.

Reviewed rule map: 10038 CSP, 10021 MIME sniffing, 10020 framing, 10035 HSTS
(D1); 10036 Server and 10037 X-Powered-By disclosure (D3); 10010 HttpOnly,
10011 Secure, 10054 SameSite (D2). Cookie equivalence requires the exact
`MoodleSession` name. Additional independent D3 rules: 10015 cache directives,
10023 debug disclosure, 10027 suspicious comments, 90022 application errors.
No rule maps to D6.

A reviewed deployment control key groups native/ZAP reports of the same control;
all observed resource/member evidence is retained. Unrelated headers and
unmapped rules stay distinct. Canonical contribution uses the maximum eligible
source contribution under the existing coefficients, never a sum. Source
conflicts are exposed. More sources do not create an additional penalty;
different evidence strength/severity can change the maximum transparently.
NOT_REEVALUATED metadata is not independent corroborating evidence.

Export is allowlisted structural alert metadata, evidence digest/size, rule/CWE/
WASC/reference, safe request paths, status and response hashes. Arbitrary alert
payloads, attack/otherInfo, query values, tokens, cookies, raw bodies and API keys
are never written. The full in-memory alert report SHA256 is retained, while the
stored JSON is explicitly sanitized evidence, not a claim to retain secret raw
messages. Static rule titles/remediation references avoid copying server-derived
free text. Snapshot artifact manifests hash every exported file except themselves.

## Fusion/CQI and limitations

Canonical rows feed the unchanged Fusion/CQI library. Current contextual links
require freshly observed eligible FAIL/PARTIAL evidence; coverage-only historical
check identities cannot create a current vulnerability association. Correlation
is contextual, non-causal, score_effect=NONE. VERSION_BASED never becomes exploit
confirmation. Duplicate-source maximum plus the existing transport/patch/root
rules prevent duplicate penalties. Equal baseline weights remain 1/6.

Unauthenticated/public coverage only: AUTHENTICATED_ZAP_COVERAGE=NOT_VALIDATED.
Passive scanning cannot establish all SQLi, XSS or access-control vulnerabilities.
Moodle lab validation does not establish equivalent performance on other LMS.
The stable pre-ZAP release is unchanged and remains the demonstration fallback.

## Future extension contracts (documentation only)

Nuclei/TLS/network/SBOM providers can implement the same provider/domain contract.
A future SafeActiveValidator or ZapAuthorizedActiveProvider needs a separately
reviewed profile, scope, non-destructive predicates and evidence semantics.
Existing accepted Branch 1 active validators remain untouched and are not invoked
by this workflow. No ZAP active scanner is implemented or exposed here.
