# M5A — Live Generalization Diagnostic

The automatically discovered session is `runtime/demo/31aff64be5fd482ebfbd2679f157ab73/live_001`. All 130 source records were recovered by bounded offsets with inode/device and individual byte-hash verification; no full-log scan or network request was made. Raw requests, queries, tokens, cookies, referrers and user agents are not copied into M5 artifacts.

The operator reports ordinary browsing. HTTP evidence is compatible with Moodle navigation, but does not independently adjudicate user intent or prove authentication success. This session is EXTERNAL DIAGNOSTIC HOLDOUT, not labelled training data.

| Sequence | UTC window start | Requests | v1 decision | IF decision | XGB BENIGN score (uncalibrated) |
| --- | --- | --- | --- | --- | --- |
| 1 | 2026-10-09T19:45:00+00:00 | 4 | BENIGN | 0.046044 | 0.963148 |
| 2 | 2026-10-09T19:45:10+00:00 | 2 | UNCERTAIN | 0.000187 | 0.737529 |
| 3 | 2026-10-09T19:45:50+00:00 | 3 | BENIGN | 0.046700 | 0.986265 |
| 4 | 2026-10-09T19:46:00+00:00 | 2 | UNCERTAIN | 0.001852 | 0.733664 |
| 5 | 2026-10-09T19:46:40+00:00 | 2 | BENIGN | 0.055746 | 0.960958 |
| 6 | 2026-10-09T19:47:00+00:00 | 7 | UNKNOWN_ANOMALY | -0.019550 | 0.991283 |
| 7 | 2026-10-09T19:47:50+00:00 | 74 | UNKNOWN_ANOMALY | -0.177323 | 0.988019 |
| 8 | 2026-10-09T19:48:00+00:00 | 28 | UNKNOWN_ANOMALY | -0.112505 | 0.993242 |
| 9 | 2026-10-09T20:11:20+00:00 | 1 | BENIGN | 0.058372 | 0.861016 |
| 10 | 2026-10-09T20:11:30+00:00 | 5 | UNKNOWN_ANOMALY | -0.010458 | 0.906338 |
| 11 | 2026-10-09T20:11:40+00:00 | 2 | UNCERTAIN | 0.000187 | 0.737529 |

Negative IF decision means anomalous. The accepted package uses contamination=0.15, selected in M2C, and confidence threshold=0.8. It does not use the recalled fixed 0.1.

## Feature evidence

All 65 features for all 11 windows, TRAIN/VALIDATION/TEST benign summary distributions, medians, MAD/IQR, robust deviations and TRAIN empirical midrank percentiles are in `outputs/branch2/m5/diagnostic_02/diagnostic.json`. Robust deviation is descriptive, not an IF causal attribution.

### Sequence 6

| Feature | Observed | TRAIN median | TRAIN max | Absolute robust deviation |
| --- | --- | --- | --- | --- |
| query_length_max | 1469.000 | 17.500 | 1752.000 | 55.944 |
| query_length_mean | 271.429 | 8.688 | 315.400 | 20.399 |
| quote_count | 144.000 | 0.000 | 296.000 | 14.389 |
| url_encoded_count | 250.000 | 0.000 | 539.000 | 12.491 |
| suspicious_query_ratio | 0.286 | 0.000 | 0.600 | 8.736 |
| ajax_request_count | 4.000 | 0.500 | 13.000 | 4.721 |
| url_encoded_ratio | 0.395 | 0.000 | 0.468 | 4.654 |
| parameter_count_total | 12.000 | 2.000 | 33.000 | 3.372 |

Semantic request counts: AJAX_SERVICE=4, AUTH_LOGIN=2, COURSE_VIEW=1.

| Category | Quotes | Encoded tokens | Max query length | JSON args observations |
| --- | --- | --- | --- | --- |
| AJAX_SERVICE | 144.0 | 250.0 | 1469.0 | 2 |
| AUTH_LOGIN | 0.0 | 0.0 | 13.0 | 0 |
| COURSE_VIEW | 0.0 | 0.0 | 4.0 | 0 |

### Sequence 7

| Feature | Observed | TRAIN median | TRAIN max | Absolute robust deviation |
| --- | --- | --- | --- | --- |
| quote_count | 780.000 | 0.000 | 296.000 | 77.942 |
| url_encoded_count | 1454.000 | 0.000 | 539.000 | 72.646 |
| query_length_max | 1760.000 | 17.500 | 1752.000 | 67.160 |
| parameter_count_total | 145.000 | 2.000 | 33.000 | 48.226 |
| get_count | 68.000 | 4.000 | 15.000 | 43.167 |
| ajax_request_count | 30.000 | 0.500 | 13.000 | 39.795 |
| query_present_count | 39.000 | 1.000 | 13.000 | 25.631 |
| unique_paths | 41.000 | 3.000 | 10.000 | 25.631 |

Semantic request counts: AJAX_SERVICE=30, COURSE_VIEW=1, DASHBOARD=1, OTHER_NAVIGATION=3, STATIC_ASSET=29, THEME_RESOURCE=9, UNKNOWN=1.

| Category | Quotes | Encoded tokens | Max query length | JSON args observations |
| --- | --- | --- | --- | --- |
| AJAX_SERVICE | 780.0 | 1454.0 | 1760.0 | 24 |
| COURSE_VIEW | 0.0 | 0.0 | 4.0 | 0 |
| DASHBOARD | 0.0 | 0.0 | 0.0 | 0 |
| OTHER_NAVIGATION | 0.0 | 0.0 | 10.0 | 0 |
| STATIC_ASSET | 0.0 | 0.0 | 0.0 | 0 |
| THEME_RESOURCE | 0.0 | 0.0 | 951.0 | 0 |
| UNKNOWN | 0.0 | 0.0 | 0.0 | 0 |

### Sequence 8

| Feature | Observed | TRAIN median | TRAIN max | Absolute robust deviation |
| --- | --- | --- | --- | --- |
| query_length_max | 951.000 | 17.500 | 1752.000 | 35.979 |
| response_bytes_max | 252940.000 | 23603.500 | 236394.000 | 21.003 |
| parameter_count_total | 61.000 | 2.000 | 33.000 | 19.897 |
| get_count | 25.000 | 4.000 | 15.000 | 14.164 |
| unique_paths | 23.000 | 3.000 | 10.000 | 13.490 |
| resource_breadth | 21.000 | 3.000 | 9.000 | 12.141 |
| response_bytes_total | 759344.000 | 63997.000 | 1032567.000 | 9.787 |
| status_2xx_count | 28.000 | 5.000 | 17.000 | 7.757 |

Semantic request counts: AJAX_SERVICE=4, DASHBOARD=1, OTHER_NAVIGATION=1, STATIC_ASSET=18, THEME_RESOURCE=4.

| Category | Quotes | Encoded tokens | Max query length | JSON args observations |
| --- | --- | --- | --- | --- |
| AJAX_SERVICE | 18.0 | 36.0 | 220.0 | 1 |
| DASHBOARD | 0.0 | 0.0 | 0.0 | 0 |
| OTHER_NAVIGATION | 0.0 | 0.0 | 0.0 | 0 |
| STATIC_ASSET | 0.0 | 0.0 | 0.0 | 0 |
| THEME_RESOURCE | 0.0 | 0.0 | 951.0 | 0 |

### Sequence 10

| Feature | Observed | TRAIN median | TRAIN max | Absolute robust deviation |
| --- | --- | --- | --- | --- |
| query_length_max | 885.000 | 17.500 | 1752.000 | 33.435 |
| query_length_mean | 190.600 | 8.688 | 315.400 | 14.124 |
| quote_count | 72.000 | 0.000 | 296.000 | 7.195 |
| url_encoded_count | 124.000 | 0.000 | 539.000 | 6.195 |
| suspicious_query_ratio | 0.200 | 0.000 | 0.600 | 6.115 |
| url_encoded_ratio | 0.390 | 0.000 | 0.468 | 4.603 |
| ajax_request_count | 2.000 | 0.500 | 13.000 | 2.023 |
| login_request_count | 2.000 | 0.000 | 3.000 | 2.000 |

Semantic request counts: AJAX_SERVICE=2, AUTH_LOGIN=1, AUTH_LOGOUT=1, OTHER_NAVIGATION=1.

| Category | Quotes | Encoded tokens | Max query length | JSON args observations |
| --- | --- | --- | --- | --- |
| AJAX_SERVICE | 72.0 | 124.0 | 885.0 | 1 |
| AUTH_LOGIN | 0.0 | 0.0 | 0.0 | 0 |
| AUTH_LOGOUT | 0.0 | 0.0 | 18.0 | 0 |
| OTHER_NAVIGATION | 0.0 | 0.0 | 0.0 | 0 |

The 19:47:00 window has only seven requests, yet long/encoded AJAX JSON query arguments. The 19:47:50 window has 74 requests (38 assets/theme, 30 AJAX); the next has 28 (22 assets/theme, four AJAX). All 780 quotes and 1,454 encoding tokens in the 74-request window occur on AJAX requests; 24 AJAX observations contain syntactically valid JSON `args`. Installed Moodle `lib/ajax/service.php` reads `args` and uses `json_decode`; JSON quotes are expected syntax. Theme query strings also trigger six SQL lexical tokens per heavy window; token matching alone is not SQL injection evidence.

This supports a domain/feature-context mismatch hypothesis: query punctuation, resource fan-out and breadth differ from the benign reference. It does not prove which feature caused the IF decision. The 20:11:30 anomaly includes a logout path, AJAX and login navigation, with quotes/encoding again confined to AJAX. No POST body, session identity or role is inferred.

## Dataset v2 benign coverage

| Scenario | Status | Windows | Runs | Notes |
| --- | --- | --- | --- | --- |
| login_endpoint | PRESENT | 21 | B01-run01, B01-run02, B01-run03, B02-run01, B02-run02, B03-run01, B03-run02, B04-run51, B04-run52, B04-run53, BN02-run52 | Observed path/method/status; does not prove completed user action |
| login_POST | PRESENT | 12 | B01-run01, B01-run02, B01-run03, B02-run01, B02-run02, B03-run01, B03-run02, B04-run51, B04-run52, B04-run53 | Observed path/method/status; does not prove completed user action |
| logout | PRESENT | 3 | B01-run02, B01-run03, B02-run01 | Observed path/method/status; does not prove completed user action |
| dashboard | PRESENT | 29 | B01-run01, B01-run02, B01-run03, B02-run01, B02-run02, B03-run01, B03-run02, B04-run51, B04-run52, B04-run53 | Observed path/method/status; does not prove completed user action |
| course_navigation | PRESENT | 12 | B01-run02, B01-run03, B02-run01, B02-run02, B03-run01, B03-run02 | Observed path/method/status; does not prove completed user action |
| profile | PRESENT | 2 | B01-run03, B02-run01 | Observed path/method/status; does not prove completed user action |
| quiz_navigation | PRESENT | 16 | B01-run01, B01-run02, B01-run03, B02-run01, B03-run01, B03-run02 | Observed path/method/status; does not prove completed user action |
| AJAX | PRESENT | 41 | B01-run01, B01-run02, B01-run03, B02-run01, B02-run02, B03-run01, B03-run02 | Observed path/method/status; does not prove completed user action |
| theme_static | PRESENT | 27 | B01-run01, B01-run02, B01-run03, B02-run01, B02-run02, B03-run01, B03-run02, BN02-run51, BN02-run52 | Observed path/method/status; does not prove completed user action |
| POST | PRESENT | 54 | B01-run01, B01-run02, B01-run03, B02-run01, B02-run02, B03-run01, B03-run02, B04-run51, B04-run52, B04-run53 | Observed path/method/status; does not prove completed user action |
| redirect | PRESENT | 35 | B01-run01, B01-run02, B01-run03, B02-run01, B02-run02, B03-run01, B03-run02, B04-run51, B04-run52, B04-run53 | Observed path/method/status; does not prove completed user action |
| successful_login | PROTOCOL_SUPPORTED | 15 | B04-run51, B04-run52, B04-run53 | B04 administrator bootstrap includes identity verification; COMPLETE worker protocol supports login, not a browser asset load |
| incorrect_then_successful_login | NOT_PROVEN | None |  | Requires session-linked action/audit or independent protocol evidence; Apache HTTP status is insufficient |
| course_switching | NOT_PROVEN | None |  | Requires session-linked action/audit or independent protocol evidence; Apache HTTP status is insufficient |
| multiple_roles | PARTIAL_ADMIN_ONLY | None | B04-run51, B04-run52, B04-run53 | Administrator protocol supported; no separately verified student/teacher browser protocols established here |
| rapid_browsing | ABSENT | 0 |  | Predeclared rate proxy only: >=2 or <=0.2 requests/s; human browsing not established |
| slow_browsing | PROXY_PRESENT | 15 | B01-run01, B01-run02, B01-run03, B02-run01, B04-run51, B04-run52, B04-run53, BN02-run52 | Predeclared rate proxy only: >=2 or <=0.2 requests/s; human browsing not established |

Historical browser-like paths exist, so “no AJAX/assets in training” would be false. However rapid-browser fan-out is not represented by the >=2 requests/s proxy. B04 COMPLETE manifests plus the identity-verifying bootstrap support administrator login/navigation, but these synthetic HTTP clients do not load embedded assets like a browser. Incorrect-password-then-success and verified multi-role browser protocols are not established.
