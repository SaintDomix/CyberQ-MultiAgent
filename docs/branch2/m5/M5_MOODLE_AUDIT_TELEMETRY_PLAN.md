# Moodle audit telemetry feasibility

Read-only local source inspection confirms installed standard and external
database log-store code. `admin/tool/log/store/standard/classes/log/store.php`
implements Moodle's internal SQL log reader and writes `logstore_standard_log`;
`db/install.xml` declares its schema. This proves capability exists, **not**
that the store is enabled, populated, or retained for the October9 session.
Existing accepted internal evidence does not contain enabled log-store state.
No DB connection, credentials access, schema change, event export or HTTP
request was performed for this feasibility review.

| Available source field | Future canonical mapping | Privacy treatment / caveat |
| --- | --- | --- |
| id, timecreated | source event ID, UTC event time | Exact time necessary for joining; restrict retention/access |
| eventname, component, action, target, crud, edulevel | typed application action | Explicit whitelist; semantics are logged observations |
| userid, realuserid, relateduserid | actor/impersonation/related-actor pseudonyms | Keyed HMAC with environment-supplied study key; never user names/email |
| courseid, objectid/objecttable | pseudonymous course/resource context | Export whitelisted types and keyed IDs only |
| contextid/contextlevel/contextinstanceid | application context | Context is **not automatically a role**; historical role resolution requires separately dated evidence |
| origin | browser/CLI/cron/webservice origin | Helps distinguish infrastructure activity |
| ip | optional client pseudonym | HMAC; no raw IP in exported features |
| anonymous | source anonymity indicator | Respect anonymous semantics; do not backfill identity |
| other | deliberately omitted | May contain sensitive content; no blanket JSON export |

Core login/logout/failure event classes can support independent authentication
outcome review, and course/resource events can distinguish a human action from
HTTP asset fan-out. Installed event definitions and enabled logger settings
must be checked for each export. Standard log fields do not provide a session
cookie/ID. Never infer session identity solely from IP; many users may share it.
Timestamp alignment plus a pseudonymous actor is contextual evidence, not a
causal proof or guaranteed one-to-one HTTP join.

## Secure later export

Use a dedicated server-local read-only database account restricted to the
whitelisted table/columns and an approved UTC range. Supply credentials via
environment or a server-owned secret manager; do not put password/token in
arguments, documentation, repository JSON or error messages. Do not read or
print `config.php` DB secrets for convenience. A Moodle CLI adapter may use
its existing privileged configuration without printing it, but this needs
separate authorization and code review. Export only sanitized canonical fields
plus schema/version/query-range/source digest and row-count provenance.

First verify enabled store, retention and actual available dates with read-only
counts. If absent, record unavailable; never fabricate past events. Independent
protocol diaries are another source but must be distinguished from audit logs.

Complexity is moderate: bounded exporter, HMAC identity adapter, timestamp
join-quality reporting and privacy tests. A useful first integration would
adjudicate successful login/logout and course actions; fitting a role-aware
model requires enough separately captured roles and explicit leakage-safe
session groups. No integration into accepted v1 or the M5 candidate is made.
