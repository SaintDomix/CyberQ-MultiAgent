# Application API 2.0

Loopback default: `http://127.0.0.1:8000`. OpenAPI: `/openapi.json`.
Responses use application entities rather than raw research serialization.

Read routes:

| Route | Response |
|---|---|
| GET /api/health | service availability, model integrity, no automatic execution |
| GET /api/system/status | mode, model identity, source generation, counts, runtime |
| GET /api/model | hash-verified accepted package/schema/config/limitations |
| GET /api/model/evaluation | locked benign/attack comparisons, never recalculated metrics |
| GET /api/posture/findings | paginated PostureFinding list |
| GET /api/posture/findings/{finding_id} | one finding |
| GET /api/behavior/observations | paginated newest-first BehaviorObservation list |
| GET /api/behavior/incidents | paginated Incident list |
| GET /api/behavior/incidents/{episode_id} | incident detail |
| GET /api/fusion/events | paginated contextual FusionEvent list |
| GET /api/cqi | full index, six dimensions, contributors, policy, sensitivity |
| GET /api/cqi/dimensions | six normalized dimension summaries |
| GET /api/evidence/{id} | allowlisted entity lookup; never a file/path API |
| GET /api/runtime/status | source/checkpoint/journal/process metadata |
| GET /api/research/benign-comparison | locked candidate/v1 benign metrics |
| GET /api/research/attack-comparison | locked candidate/v1 attempt metrics |
| GET /api/explainability/{observation_id} | upstream SHAP and robust deviations |
| GET /api/application/snapshot | coherent dashboard domain bundle |
| GET /report.html | explicitly historical Model v1 M3C report |

Common evidence query parameters: `mode=ACCEPTED_REPLAY|LIVE_LAB`,
`replay=ATTACK_HOLDOUT|BENIGN_TEST`, optional reserved `run_id`.
No parameter specifies a file, URL, shell command or model path.

Pagination returns `{items,total,offset,limit,mode}`; limit 1–200, default 50.
Posture filters: status/category/dimension/severity. Observation filters:
label/status. Incident filters: label/severity/status. Missing entities return
404. Invalid parameters return 422 with rejected values withheld. Unavailable
or corrupt required sources return 503; the coherent snapshot may instead
return an explicit source error with empty behavior and null CQI.

POST `/api/runtime/start` and `/api/runtime/stop` require an empty JSON body,
`X-Product-Control: 1` and a local Origin when supplied. Model verification gates
start. Controls never generate traffic or refit models. Missing Apache read
permission is reported, not bypassed. GET calls never start a process.

Responses withhold raw records, passwords, tokens, cookies and POST bodies.
Evidence is a sanitized allowlist. XGBoost uses `UNCALIBRATED_MODEL_SCORE`.
Model corruption is `FAILED`; runtime availability alone does not prove a live
process. No fallback from LIVE_LAB to replay occurs implicitly.
