# Test Coverage Analysis

## Current State

The codebase currently has **zero test coverage**. There are no unit tests, integration tests, test configuration files, or CI/CD pipelines that run tests. The project contains three source files:

| File | Language | Lines | Description |
|------|----------|-------|-------------|
| `Sast/Horusec/Horusec_Report/horusec_json2md.py` | Python | 167 | Converts Horusec JSON reports to Markdown |
| `Sast/Horusec/validate_horusec_report.sh` | Bash | 149 | Validates reports and controls pipeline exit codes |
| `Sast/Horusec/horusec_docker_linux.sh` | Bash | 47 | Runs Horusec via Docker |

---

## Recommended Test Coverage Improvements

### Priority 1 (High): `horusec_json2md.py` - Python Unit Tests

This is the most testable file and carries the highest risk of regressions. It has well-defined pure functions that are straightforward to test with `pytest`.

#### Functions to test:

**`clean_text(text)`** (line 25)
- Verify newlines (`\n`, `\r`) are replaced with spaces
- Verify pipe characters (`|`) are replaced with spaces (important for Markdown tables)
- Test empty string input
- Test string with no special characters (passthrough)

**`clean_summary(summary)`** (line 30)
- Verify the known prefix `"(1/1) * Possible vulnerability detected: "` is stripped
- Verify strings without the prefix are returned unchanged
- Test empty string input

**`severity_icon(severity)`** (line 49)
- Test each known severity level: CRITICAL, HIGH, MEDIUM, LOW, INFO
- Verify case-insensitivity (e.g., `"critical"` vs `"CRITICAL"`)
- Test unknown severity returns empty string
- Test empty string input

**`read_horusec_json(file_path)`** (line 19)
- Test reading a valid JSON file returns parsed dict
- Test behavior with malformed JSON (should raise `json.JSONDecodeError`)
- Test behavior with non-existent file (should raise `FileNotFoundError`)
- Test UTF-8 encoded content is handled correctly

**`generate_markdown(data, output_path)`** (line 60)
- Test with empty `analysisVulnerabilities` list (should write "Nenhuma vulnerabilidade encontrada")
- Test with a single vulnerability (verify table headers, row content, and description section)
- Test with multiple vulnerabilities of different severities
- Test summary truncation at 254 characters
- Test vulnerability details with and without newlines (split logic at line 107-108 and 128-129)
- Test missing/optional fields use `'N/A'` fallback
- Test Markdown output structure (headers, table formatting, separators)

**`main()`** (line 150)
- Test CLI argument parsing (missing args, valid args)
- Test end-to-end: JSON input file -> Markdown output file

#### Suggested test fixtures:

Create sample JSON files representing:
1. A report with zero vulnerabilities
2. A report with one vulnerability of each severity
3. A report with vulnerabilities that have long summaries (>254 chars)
4. A report with special characters in vulnerability details (`|`, `\n`, `\r`)
5. A minimal report with missing optional fields

---

### Priority 2 (High): `validate_horusec_report.sh` - Shell Integration Tests

This script controls CI/CD pipeline pass/fail decisions, making it critical for reliability. Testing with [bats-core](https://github.com/bats-core/bats-core) (Bash Automated Testing System) is recommended.

#### Test scenarios:

**Input validation**
- Missing report file: verify exit code 1 and error message
- Invalid JSON file: verify exit code 1 and error message
- JSON missing required fields (`version`, `id`, `status`, `createdAt`, `finishedAt`, `analysisVulnerabilities`): verify exit code 1 for each

**Vulnerability counting**
- Report with 0 vulnerabilities: verify all counts are 0 and exit code is 0
- Report with only LOW/MEDIUM vulnerabilities: verify exit code 0 (pipeline passes)
- Report with CRITICAL vulnerabilities: verify exit code 1 (pipeline blocked)
- Report with HIGH vulnerabilities: verify exit code 1 (pipeline blocked)
- Report with mixed severities: verify counts match expected values

**Bypass list logic**
- Vulnerability matching `BYPASS_RULE_ID_LIST` rule_id: verify it is excluded from blocking count
- Vulnerability matching `BYPASS_VULNERABILITY_ID_LIST` vulnerability ID: verify it is excluded from blocking count
- CRITICAL/HIGH vulnerability in bypass list: verify exit code 0 when all blocking vulns are bypassed
- Verify bypassed counts are computed correctly (`CRITICAS_BYPASSED`, `ALTAS_BYPASSED`)

**Output format**
- Verify table formatting is consistent
- Verify warning messages appear when critical/high vulnerabilities are found
- Verify success message appears when pipeline can continue

#### Suggested test fixtures:

Create sample JSON report files under a `tests/fixtures/` directory:
1. `empty_report.json` - valid structure, no vulnerabilities
2. `critical_vulns.json` - contains CRITICAL severity vulnerabilities
3. `high_vulns.json` - contains HIGH severity vulnerabilities
4. `bypassed_vulns.json` - all critical/high vulns match bypass lists
5. `mixed_vulns.json` - mix of severities, some bypassed
6. `invalid.json` - malformed JSON
7. `missing_fields.json` - valid JSON but missing required fields

---

### Priority 3 (Medium): `horusec_docker_linux.sh` - Shell Tests

This script mostly orchestrates Docker commands, making it harder to unit test. However, some aspects can be tested.

#### Test scenarios:

**Directory creation logic**
- Verify `reports/` directory is created when it doesn't exist
- Verify existing `reports/` directory is not recreated (message "Diretorio ja existe")

**Configuration validation**
- Verify the Docker image tag matches expected version
- Verify severity exceptions, ignore patterns, and report paths are set correctly

**Docker command construction** (requires mocking `docker`)
- Mock `docker pull` and `docker run` to verify the correct image and arguments are passed
- Verify volume mounts, ignore paths, and output path are correctly composed

---

### Priority 4 (Medium): Infrastructure & CI

#### Test framework setup
- Add `pytest` to `requirements.txt` (or create a `requirements-dev.txt`)
- Add a `pytest.ini` or `pyproject.toml` with test configuration
- Install `bats-core` for shell script testing

#### CI/CD pipeline
- Add a GitHub Actions workflow (`.github/workflows/test.yml`) that runs:
  - `pytest` for Python tests
  - `bats` for shell script tests
- Run tests on pull requests and pushes to main

#### Code quality
- Add `flake8` or `ruff` for Python linting
- Add `shellcheck` for shell script linting

---

## Suggested Project Structure

```
appsec-tools/
├── Sast/
│   └── Horusec/
│       ├── horusec_docker_linux.sh
│       ├── validate_horusec_report.sh
│       └── Horusec_Report/
│           ├── horusec_json2md.py
│           └── requirements.txt
├── tests/
│   ├── fixtures/
│   │   ├── empty_report.json
│   │   ├── single_vuln_report.json
│   │   ├── multi_vuln_report.json
│   │   ├── long_summary_report.json
│   │   ├── special_chars_report.json
│   │   ├── critical_vulns.json
│   │   ├── high_vulns.json
│   │   ├── bypassed_vulns.json
│   │   ├── mixed_vulns.json
│   │   ├── invalid.json
│   │   └── missing_fields.json
│   ├── test_horusec_json2md.py
│   ├── test_validate_horusec_report.bats
│   └── test_horusec_docker_linux.bats
├── requirements-dev.txt
├── pyproject.toml
├── README.md
└── TEST_COVERAGE_ANALYSIS.md
```

---

## Summary

| Area | Priority | Effort | Impact |
|------|----------|--------|--------|
| `horusec_json2md.py` unit tests | High | Low | High - Pure functions, easy to test, prevents Markdown generation regressions |
| `validate_horusec_report.sh` integration tests | High | Medium | High - Controls pipeline pass/fail, bypass logic is error-prone |
| `horusec_docker_linux.sh` tests | Medium | Medium | Medium - Docker orchestration, mostly configuration validation |
| CI/CD pipeline for tests | Medium | Low | High - Ensures tests are actually run on every change |
| Linting (shellcheck, ruff) | Medium | Low | Medium - Catches bugs early, enforces code standards |
