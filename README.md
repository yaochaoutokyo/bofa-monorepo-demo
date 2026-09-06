# bofa-monorepo-demo

A simulated Bank of America compliance-critical monorepo used to demonstrate Devin raising
test coverage on regulated code in a short live session.

## The scenario

An OCC examination flagged that the bank's core services average roughly **30% line coverage**,
and that the untested 70% is concentrated exactly where regulators care most: error handling,
input/data validation, transaction limits, PII masking and audit-trail completeness. Several
services have no CI test job at all, so nobody notices when coverage slips.

The engineering team must show measurable progress before the follow-up exam. This repo is the
"before" state: three small microservices, each with ~1000 lines of realistic production logic,
each with a working test runner and coverage tool, and each with a deliberately tiny happy-path
test suite. The demo task for Devin is: *pick a service, write edge-case tests for the
compliance-critical paths, and report the before/after coverage.*

Regulatory framing used by the services (paraphrased):

| Service | Domain | Controls it evidences |
|---|---|---|
| `services/transaction-java` | Transaction processing, fees, FX, interest, audit logging | OCC internal control, SOX 404 accuracy, Reg E fee/disclosure rules, BSA/AML CTR + structuring detection |
| `services/auth-typescript` | Authentication, sessions, tokens, MFA, lockout, roles, PII masking | FFIEC authentication guidance, PCI-DSS 8 (auth) and 3.3 (PAN masking), GLBA safeguards |
| `services/validation-python` | Field validation, sanitization, normalization, masking, KYC/AML rules, audit log | 31 CFR 1020.220 CIP, FinCEN CDD, NACHA routing checks, PCI-DSS 10 audit trail |

## Baseline coverage (measured)

| Service | Runner / coverage tool | Tests | Line coverage | Suite runtime |
|---|---|---|---|---|
| `transaction-java` | JUnit 5 + JaCoCo (Maven) | 2 | **29.0%** (257 / 886 lines) | ~0.1s tests, ~2s `mvn test` |
| `auth-typescript` | Jest + ts-jest, built-in coverage | 2 | **28.2%** lines (14.1% branches) | ~1.5s |
| `validation-python` | pytest + pytest-cov (branch mode) | 9 | **32.5%** | ~0.2s |

Production source size (excluding tests and config): Java 12 files / 1732 lines (886 executable),
TypeScript 11 files / 1572 lines, Python 9 files / 1477 lines.

What the baseline tests cover: registering an account and posting a deposit/withdrawal (Java),
user registration and email masking (TypeScript), a handful of validators, SSN/card masking,
one successful audit entry and a clean transaction record (Python).

What they do **not** cover: every error branch, every validation rejection, boundary checks,
FX/interest rounding, overdraft and fee waivers, token expiry, lockout escalation, session
timeouts, MFA parsing, role escalation, routing-number checksums, structuring detection,
timestamp handling in audit logs, and more.

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
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
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

1. Show the baseline: run one service's coverage command, point at the ~30% number and the
   long list of uncovered lines in the report.
2. Ask Devin to add edge-case tests for a named compliance-critical area (e.g. "negative and
   zero amounts, overflow and fee rounding in `TransactionProcessor` / `FeeCalculator`",
   or "token expiry, lockout and PII masking in the auth service").
3. Re-run coverage. Devin's new tests will also surface real defects in the previously
   untested paths; the expected convention is to keep those tests, mark them as known defects,
   and list them in the PR rather than changing production code in the same PR.
