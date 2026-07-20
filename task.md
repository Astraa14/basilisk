# Basilisk v2.0 — Implementation Tasks

## Phase 1: Core Infrastructure
- [x] Update `models.py` — new fields, enum values, ScanConfig
- [x] Create `scoring.py` — CVSS v3.1 engine
- [x] Create `concurrent.py` — ThreadPoolExecutor scanner
- [x] Create `adaptive.py` — Adaptive payload evolution
- [x] Create `encoding.py` — Encoding/obfuscation system
- [x] Update `engine.py` — Integrate concurrent + adaptive
- [x] Update `core.py` — New params + concurrent wiring
- [x] Update `pyproject.toml` — Version bump + optional deps

## Phase 2: New Vulnerability Detectors
- [x] Create `detectors/__init__.py` — Package init
- [x] Create `detectors/xxe.py` — XXE injection
- [x] Create `detectors/graphql.py` — GraphQL injection
- [x] Create `detectors/bola.py` — Broken Object Level Auth
- [x] Create `detectors/prototype_pollution.py`
- [x] Create `detectors/ssti_advanced.py` — Multi-engine SSTI
- [x] Create `detectors/ssrf_oob.py` — Blind SSRF with OOB
- [x] Create `detectors/websocket.py` — WebSocket fuzzing
- [x] Create `detectors/race_condition.py`
- [x] Create `detectors/ldap.py` — LDAP injection
- [x] Create `detectors/business_logic.py`
- [x] Create `detectors/info_disclosure.py`

## Phase 3: Authentication & Authorization
- [x] Create `detectors/auth_bypass.py` — JWT/OAuth2/SAML
- [x] Create `detectors/csrf.py` — CSRF token handling
- [x] Create `detectors/privilege_escalation.py`
- [x] Create `detectors/credential_stuffing.py`

## Phase 4: Advanced Detection & Evasion
- [x] Create `waf.py` — WAF detection + evasion
- [x] Create `detectors/blind_sqli.py` — Improved blind SQLi
- [x] Create `detectors/dom_xss.py` — Headless browser DOM XSS
- [x] Create `grammar.py` — Payload grammar system
- [x] Create `detectors/payload_chain.py` — Multi-stage chaining

## Phase 5: ML & Intelligence
- [x] Create `ml/__init__.py`
- [x] Create `ml/classifier.py` — ML vulnerability classifier
- [x] Create `ml/exploit_patterns.py` — Exploit pattern recognition
- [x] Create `detectors/zero_day.py` — Zero-day heuristics
- [x] Create `detectors/container_escape.py`
- [x] Create `detectors/network_segmentation.py`
- [x] Create `api_enum.py` — API schema enumeration
- [x] Create `dependency_check.py` — OWASP dep check

## Phase 6: Specialized & Compliance
- [x] Create `detectors/cms.py` — CMS-specific detection
- [x] Create `detectors/mobile_api.py`
- [x] Create `compliance.py` — GDPR/HIPAA/PCI-DSS
- [x] Create `detectors/visual_regression.py`
- [x] Create `mutation.py` — Mutation engine
- [x] Update `cli.py` — All new flags + subcommands
- [x] Update `judge.py` — Integrate all new evaluators

## Verification
- [x] Run existing tests (no regressions)
- [x] Run new tests for all modules
- [x] Integration test with `basilisk scan`
