# Dataset v2 feature schema

Version `dataset-v2-features-1.0`; 65 numerical features in exact saved order.
Names replace historical aliases (request_rate=old requests_per_second,
response_bytes_*=old bytes_out_*, active_span=old active_span_sec).
Repeated-path ratio counts excess repeated requests; path_repetition_ratio
retains old maximum-per-path/count concentration.

| Order | Feature |
|---:|---|
| 1 | `request_count` |
| 2 | `request_rate` |
| 3 | `active_span` |
| 4 | `mean_inter_request` |
| 5 | `min_inter_request` |
| 6 | `max_inter_request` |
| 7 | `std_inter_request` |
| 8 | `unique_paths` |
| 9 | `unique_path_ratio` |
| 10 | `repeated_path_ratio` |
| 11 | `max_requests_same_path` |
| 12 | `path_repetition_ratio` |
| 13 | `resource_breadth` |
| 14 | `login_request_count` |
| 15 | `login_request_ratio` |
| 16 | `admin_request_count` |
| 17 | `admin_request_ratio` |
| 18 | `ajax_request_count` |
| 19 | `ajax_request_ratio` |
| 20 | `api_request_count` |
| 21 | `api_request_ratio` |
| 22 | `get_count` |
| 23 | `get_ratio` |
| 24 | `post_count` |
| 25 | `post_ratio` |
| 26 | `other_method_count` |
| 27 | `other_method_ratio` |
| 28 | `status_1xx_count` |
| 29 | `status_2xx_count` |
| 30 | `status_3xx_count` |
| 31 | `status_4xx_count` |
| 32 | `status_5xx_count` |
| 33 | `redirect_ratio` |
| 34 | `client_error_ratio` |
| 35 | `server_error_ratio` |
| 36 | `error_ratio` |
| 37 | `response_bytes_total` |
| 38 | `response_bytes_mean` |
| 39 | `response_bytes_max` |
| 40 | `response_bytes_std` |
| 41 | `response_bytes_observed_ratio` |
| 42 | `query_present_count` |
| 43 | `query_present_ratio` |
| 44 | `query_length_mean` |
| 45 | `query_length_max` |
| 46 | `parameter_count_total` |
| 47 | `parameter_count_mean` |
| 48 | `url_encoded_count` |
| 49 | `url_encoded_ratio` |
| 50 | `quote_count` |
| 51 | `comment_sequence_count` |
| 52 | `special_character_ratio` |
| 53 | `sql_token_count` |
| 54 | `xss_marker_count` |
| 55 | `traversal_count` |
| 56 | `suspicious_query_ratio` |
| 57 | `identity_observed_ratio` |
| 58 | `unique_users` |
| 59 | `requests_per_user_mean` |
| 60 | `session_observed_ratio` |
| 61 | `unique_sessions` |
| 62 | `requests_per_session_mean` |
| 63 | `role_observed_ratio` |
| 64 | `unique_roles` |
| 65 | `privileged_role_request_ratio` |

Raw-query lengths/parameter counts use observable URL input only. URL encoding
ratio is percent-triplet character coverage of raw query. Lexical indicators use
at most two decode passes. Suspicious-query ratio includes path traversal evidence
and is a lexical heuristic; no token proves an exploit. Resource breadth is the
number of distinct parent path prefixes. Byte moments exclude unknown sizes and
record observation coverage. Identity/session/role fields stay neutral when
unobserved. Each formula is implemented deterministically in features.py; model
packages bind order, rules and alignment to the schema SHA-256.
