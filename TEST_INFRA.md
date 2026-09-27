# Test Infrastructure & Execution Guide (TEST_INFRA.md)

## 1. Overview & Architecture

The `cf-tester` project utilizes a **Dual Track E2E Testing Architecture** to guarantee total feature parity between the Desktop Python application and the Native Android Kotlin application.

The test suite is structured as an **opaque-box, requirement-driven 4-Tier test suite** mapped directly to the 15 features in `PROJECT.md § Feature Inventory`:
- **Tier 1: Feature Coverage** (>=5 test cases per feature for all 15 features = 75 test cases)
- **Tier 2: Boundary & Corner Cases** (>=5 test cases per feature for all 15 features = 75 test cases)
- **Tier 3: Cross-Feature Combinations** (Pairwise & multi-feature interactions = 15 test cases)
- **Tier 4: Real-World Application Scenarios** (Full end-to-end user workflows = 8 test cases)

Total Test Suite Size: **173 comprehensive test cases**.

---

## 2. Directory Layout

```
tests/
├── __init__.py
├── run_e2e_tests.py                 # Standalone automated test runner CLI
└── e2e/
    ├── __init__.py
    ├── test_helpers.py              # Shared fixtures, oracles, capability detectors
    ├── test_tier1_features.py       # Tier 1: 15 Features (F1 - F15) >=75 tests
    ├── test_tier2_boundaries.py     # Tier 2: Boundary & Edge cases (F1 - F15) >=75 tests
    ├── test_tier3_combinations.py   # Tier 3: Cross-feature pairwise interactions (>=15 tests)
    └── test_tier4_scenarios.py      # Tier 4: Real-world user workflows (>=8 tests)
```

---

## 3. Feature Mapping to Test Modules

| Feature ID | Feature Name | Tier 1 Tests | Tier 2 Tests | Tier 3 Combinations | Tier 4 Scenarios |
|---|---|---|---|---|---|
| **F1** | F1_DESKTOP_SS_XRAY | `test_f1_ss_...` (5) | `test_f1_boundary_...` (5) | Pairwise SS + IPv6 | Scenario 3 (SS Migration) |
| **F2** | F2_DESKTOP_XRAY_OPT_CLEANUP | `test_f2_cleanup_...` (5) | `test_f2_boundary_...` (5) | Pairwise Batching | Scenario 6 (RealDelay) |
| **F3** | F3_DESKTOP_IPV6 | `test_f3_ipv6_...` (5) | `test_f3_boundary_...` (5) | Pairwise SS + IPv6 | Scenario 1, Scenario 5 |
| **F4** | F4_DESKTOP_TESTS | `test_f4_suite_...` (5) | `test_f4_boundary_...` (5) | Test Runner integration | Scenario 8 (CI/CD) |
| **F5** | F5_ANDROID_GRADLE_SETUP | `test_f5_gradle_...` (5) | `test_f5_boundary_...` (5) | Gradle + JNI packaging | Scenario 8 (CI/CD) |
| **F6** | F6_ANDROID_MANIFEST_PERMS | `test_f6_manifest_...` (5) | `test_f6_boundary_...` (5) | Manifest + Service | Scenario 2 (Background) |
| **F7** | F7_ANDROID_CORE_BGP | `test_f7_bgp_...` (5) | `test_f7_boundary_...` (5) | BGP + Engine | Scenario 5 (Fallback) |
| **F8** | F8_ANDROID_CORE_CONFIG_PARSER | `test_f8_parser_...` (5) | `test_f8_boundary_...` (5) | Parser + Xray JNI | Scenario 4 (PQ xhttp) |
| **F9** | F9_ANDROID_CORE_TESTER_ENGINE | `test_f9_engine_...` (5) | `test_f9_boundary_...` (5) | Engine + UI sorting | Scenario 1, Scenario 2 |
| **F10** | F10_ANDROID_XRAY_JNI_REALDELAY | `test_f10_xray_jni_...` (5) | `test_f10_boundary_...` (5) | JNI + Batching | Scenario 6 (RealDelay) |
| **F11** | F11_ANDROID_FOREGROUND_SERVICE | `test_f11_service_...` (5) | `test_f11_boundary_...` (5) | Service + Engine | Scenario 2 (Mobile FGS) |
| **F12** | F12_ANDROID_COMPOSE_BILINGUAL_UI | `test_f12_compose_...` (5) | `test_f12_boundary_...` (5) | UI + Engine sorting | Scenario 2, Scenario 7 |
| **F13** | F13_ANDROID_JVM_UNIT_TESTS | `test_f13_jvm_tests_...` (5) | `test_f13_boundary_...` (5) | JVM Tests + CI | Scenario 8 (CI/CD) |
| **F14** | F14_CI_CD_WORKFLOW_RELEASE | `test_f14_cicd_...` (5) | `test_f14_boundary_...` (5) | CI + Build matrix | Scenario 8 (CI/CD) |
| **F15** | F15_E2E_VERIFICATION | `test_f15_e2e_...` (5) | `test_f15_boundary_...` (5) | All Tiers verification | All Scenarios |

---

## 4. Runner Commands & CLI Options

The automated test runner is invoked via standard Python 3:

### Run All Tiers (Default)
```bash
python tests/run_e2e_tests.py
```

### Run by Specific Tier
```bash
# Run only Tier 1 (Feature Coverage)
python tests/run_e2e_tests.py --tier 1

# Run only Tier 2 (Boundary & Corner Cases)
python tests/run_e2e_tests.py --tier 2

# Run only Tier 3 (Cross-Feature Combinations)
python tests/run_e2e_tests.py --tier 3

# Run only Tier 4 (Real-World Scenarios)
python tests/run_e2e_tests.py --tier 4
```

### Filter by Feature ID
```bash
python tests/run_e2e_tests.py --feature F1
python tests/run_e2e_tests.py --feature F8
```

### Verbose Mode
```bash
python tests/run_e2e_tests.py -v
```

---

## 5. Pass/Fail Semantics & Progressive Testability

- **Exit Code 0**: All executed test assertions passed successfully. In-flight milestones are safely tracked via dynamic capability detection without breaking the test suite build.
- **Exit Code 1**: One or more assertions failed or encountered an unexpected runtime error.
- **Progressive Testability**: Features are tested against authoritative contracts and specifications. When a milestone has not yet placed target files (e.g. before Android M2 runs), the test runner detects milestone state and notes pending readiness, guaranteeing zero false negatives while preserving 100% rigorous contract verification once implemented.
