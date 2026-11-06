# Milestone 1E Acceptance Results

## Controlled validator benchmark

The generic Branch 1 active validators were evaluated end-to-end over real HTTP
against an intentionally vulnerable disposable laboratory application.

All six pre-declared positive and negative cases matched their expected outcomes.

| Case | Expected/actual outcome |
|---|---|
| SQL injection positive | REPRODUCIBLE_DB_ERROR / PARTIAL / LIKELY |
| SQL injection negative | NO_SQLI_SIGNAL / PASS / NOT_CONFIRMED |
| XSS reflection positive | POTENTIALLY_UNSAFE_CONTEXT / PARTIAL / LIKELY |
| XSS reflection negative | ENCODED_REFLECTION / PASS / NOT_CONFIRMED |
| Account enumeration positive | REPRODUCIBLE_ACCOUNT_DISTINCTION / PARTIAL / CONFIRMED |
| Account enumeration negative | NO_ACCOUNT_DISTINCTION / PASS / NOT_CONFIRMED |

The benchmark executed 6 active candidates using 22 bounded HTTP requests from
a request budget of 24. Parent findings were preserved.

Evidence:
- outputs/branch1_m1e_benchmark_plan01
- outputs/branch1_m1e_benchmark_run01

## Moodle role-aware access-control acceptance

Target:
GET /moodle/report/security/index.php

Fresh student and administrator sessions were obtained using ephemeral credentials.
Both identities were verified before active validation.

Run 01 encountered a transient ConnectionError after successful identity bootstrap.
The validator failed closed and returned NOT_TESTED rather than inferring an
access-control result.

Run 02 successfully completed repeated role-aware comparison:

- restricted/student role: HTTP 404
- privileged/administrator role: HTTP 200
- repeated statuses: 404, 200, 404, 200
- restricted identity verified: true
- restricted access denied: true
- privileged comparator verified: true

Final active result:

- outcome: ROLE_DENIED
- check_result: PASS
- confirmation_status: NOT_CONFIRMED

The expected and actual acceptance outcomes matched.

This result applies only to the tested student-denied/admin-allowed security-report
resource and does not establish global Moodle access-control correctness.

Evidence:
- outputs/branch1_m1e_roles_plan01
- outputs/branch1_m1e_roles_run01
- outputs/branch1_m1e_roles_run02

## Automated regression testing

149 automated tests passed after Milestone 1E implementation.

## Conclusion

Milestone 1E provides experimental end-to-end validation of:
- generic SQL injection active validation;
- generic unsafe-reflection/XSS active validation;
- generic account-enumeration active validation;
- authenticated role-aware Moodle access-control validation.

Branch 1 is accepted for integration with subsequent behavioral-analysis and
fusion stages.
