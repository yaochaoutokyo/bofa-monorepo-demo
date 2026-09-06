# bofa-monorepo-demo

A simulated Bank of America compliance-critical monorepo used to demonstrate Devin raising
test coverage on regulated code in a short live session.

## The scenario

An OCC examination flagged that the bank's core services average roughly **30% line coverage**,
and that the untested 70% is concentrated exactly where regulators care most: error handling,
input/data validation, transaction limits, PII masking and audit-trail completeness. Several
services have no CI test job at all, so nobody notices when coverage slips.

The engineering team must show measurable progress before the follow-up exam. This repo is the
"before" state: three small microservices with a few hundred lines of realistic production logic
each, each with a working test runner and coverage tool, and each with a deliberately tiny
happy-path test suite. The demo task for Devin is: *pick a service, write edge-case tests for the
compliance-critical paths, and report the before/after coverage.*

Regulatory framing used by the services (paraphrased):

| Service | Domain | Controls it evidences |
|---|---|---|
| `services/transaction-java` | Transaction processing, fees, FX, interest, audit logging | OCC internal control, SOX 404 accuracy, Reg E fee/disclosure rules, BSA/AML CTR + structuring detection |
| `services/auth-typescript` | Password policy, tokens, lockout, PII masking | FFIEC authentication guidance, PCI-DSS 8 (auth) and 3.3 (PAN masking), GLBA safeguards |
| `services/validation-python` | Field/transaction validation, PII masking, audit log | 31 CFR 1020.220 CIP, NACHA routing checks, PCI-DSS 3.3 masking, PCI-DSS 10 audit trail |

## Baseline coverage (measured)

| Service | Runner / coverage tool | Tests | Line coverage | Suite runtime |
|---|---|---|---|---|
| `transaction-java` | JUnit 5 + JaCoCo (Maven) | 1 | **34.8%** (202 / 581 lines) | ~0.1s tests, ~2.5s `mvn test` (warm cache) |
| `auth-typescript` | Jest + ts-jest, built-in coverage | 3 | **30.0%** lines (22.7% branches) | ~1.2s |
| `validation-python` | pytest + pytest-cov (branch mode) | 5 | **34.3%** (254 statements, 110 branches) | ~0.05s |

Production source size (excluding tests and config): Java 10 files / 1196 lines (581 executable),
TypeScript 5 files / 441 lines, Python 4 files / 351 lines.

What the baseline tests cover: registering an account and posting a deposit (Java), a compliant
password, email masking and a single failed-login attempt (TypeScript), a valid email/state/ZIP,
SSN/card masking and one successful audit entry (Python).

What they do **not** cover: every validation rejection path (`validate_transaction`,
`TransactionValidator`, `validatePassword`), routing-number and Luhn checksums, account-number
and nested-record masking, audit hash-chain verification and time-window queries, withdrawals,
overdraft and wire fees, FX/interest rounding, token expiry/revocation, lockout escalation, and
more.

## Running each service

### Java — `services/transaction-java`

```bash
cd services/transaction-java
mvn test                      # runs JUnit 5 and writes the JaCoCo report
open target/site/jacoco/index.html   # per-class / per-line HTML report
# machine-readable: target/site/jacoco/jacoco.xml and jacoco.csv
```

Requires Java 17 and Maven 3.9+. No framework dependencies; the build is a few seconds.

### TypeScript — `services/auth-typescript`

```bash
cd services/auth-typescript
npm ci
npm test                      # jest
npm run test:coverage         # jest --coverage (text + lcov + json-summary in coverage/)
npm run typecheck
```

### Python — `services/validation-python`

```bash
cd services/validation-python
pip install -e '.[test]'          # only pytest + pytest-cov; the package has no runtime deps
pytest --cov=validation_service --cov-report=term-missing
```

## CI

`.github/workflows/ci.yml` runs the TypeScript and Python suites with coverage on every push and
pull request.

### Why Java is missing from CI

Intentionally. Part of the scenario is that some compliance-critical services have a test
runner configured but no CI job wired up, so regressions and coverage drops go unnoticed.
Adding a `transaction-java` job (Java 17, `mvn test`, upload `target/site/jacoco`) is a natural
follow-up for the demo.

## Suggested demo flow (~2 minutes)

`validation-python` is the recommended live-demo target: setup is a single `pip install` of two
test packages, the whole package is ~350 lines across three modules, and the suite runs in well
under a second. `auth-typescript` is the fallback (`npm ci` takes a few seconds);
`transaction-java` is the last resort because Maven dependency resolution on a cold cache can
take a minute or more.

1. Show the baseline: run one service's coverage command, point at the ~30% number and the
   long list of uncovered lines in the report.
2. Ask Devin to add edge-case tests for a named compliance-critical area (e.g. "rejection paths
   in `validate_transaction`, the routing-number checksum, SSN/card masking and audit
   hash-chain verification", or "token expiry, lockout and PII masking in the auth service").
3. Re-run coverage. Devin's new tests will also surface real defects in the previously
   untested paths; the expected convention is to keep those tests, mark them as known defects,
   and list them in the PR rather than changing production code in the same PR.
