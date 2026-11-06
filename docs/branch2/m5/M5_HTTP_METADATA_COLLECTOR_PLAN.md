# Privacy-preserving HTTP metadata collector proposal

Apache combined logs do not expose POST bodies. Current SQL/XSS/traversal
features describe observable URL/query evidence only. No body logging or
production collector is installed in M5.

The future collector should compute bounded numerical metadata in request
memory, then discard values immediately. Emit: timestamp, keyed request/client
pseudonym, method, normalized route category, response status, content-type
family, declared/observed bounded body length, parameter-count and encoding
statistics, plus SQL/XSS/traversal lexical indicator **counts**. No raw URL
query, form body, multipart filename/content, cookie, Authorization header,
password, session ID, CSRF token, reset token or free-form value is exported.

Sensitive parameter names (password/currentpassword/newpassword/passwd,
logintoken/sesskey/token/cookie/authorization and platform-specific equivalents)
must have values excluded **before** lexical counting, not just redacted after
logging. Report excluded-sensitive-field count and truncation/unavailable flags.
Use a strict name allowlist where possible, so unrecognized fields cannot
silently leak through. Field names themselves can carry PII; persist only
normalized type/category, not arbitrary names.

JSON extraction must parse bounded depth/key/item limits, form extraction
bounded bytes/fields, and multipart extraction metadata only. Binary and
unrecognized content types stay unavailable. Never decompress unlimited data,
buffer an entire upload, or log parser errors with input contents. Malformed,
encrypted, oversized or inaccessible inputs yield UNKNOWN/NOT_OBSERVED flags,
not fabricated zero evidence. Derived vectors must remain non-invertible in
practice; rare-value/time combinations still have privacy risk and need access
controls/retention limits. Keyed linkage keys remain outside artifacts.

Potential implementation points are a reviewed Moodle middleware/plugin or
reverse-proxy/server module. Prefer the smallest hook that observes supported
formats without changing authentication, consuming the application body stream
twice, modifying responses or adding state mutation. PHP application hooks
are platform-specific; a separate canonical adapter keeps the numerical core
platform-extensible. Apache raw-body dumping/ModSecurity audit-body logging
is explicitly unsuitable.

Required acceptance tests: sensitive-value invariance, no raw-value output,
bounded parser memory/time, malformed/oversize behavior, Unicode/URL encoding,
JSON/form/multipart handling, excluded-field accounting, unchanged application
behavior, correct request linking and authoritative provenance. Evaluate
metadata utility on new independently labelled controlled captures. Never
reinterpret old POST traffic as containing observed attack tokens.

This is a feasibility plan, not a deployed sensor or a claim of body-based
detection. Integration requires a separate authorized, privacy-reviewed study.
