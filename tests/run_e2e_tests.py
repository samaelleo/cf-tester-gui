#!/usr/bin/env python3
"""
Automated Test Runner for cf-tester 4-Tier E2E Test Suite
Executes and reports on:
  - Tier 1: Feature Coverage (F1 to F15)
  - Tier 2: Boundary & Corner Cases (F1 to F15)
  - Tier 3: Cross-Feature Combinations (Pairwise interactions)
  - Tier 4: Real-World Application Scenarios (User workflows)
"""

import argparse
import os
import sys
import time
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class ColoredText:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def colorize(cls, text: str, color: str) -> str:
        if sys.stdout.isatty() or os.environ.get("FORCE_COLOR"):
            return f"{color}{text}{cls.RESET}"
        return text


class TierResultTracker(unittest.TestResult):
    def __init__(self, stream=None, descriptions=None, verbosity=None):
        super().__init__(stream, descriptions, verbosity)
        self.successes = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.successes.append(test)


def load_tier_suite(tier: int, feature_filter: str = "") -> unittest.TestSuite:
    """Loads a specific test suite tier, optionally filtering by feature ID."""
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()

    module_map = {
        1: "tests.e2e.test_tier1_features",
        2: "tests.e2e.test_tier2_boundaries",
        3: "tests.e2e.test_tier3_combinations",
        4: "tests.e2e.test_tier4_scenarios",
    }

    mod_name = module_map.get(tier)
    if not mod_name:
        return suite

    try:
        loaded = loader.loadTestsFromName(mod_name)
    except Exception as e:
        print(f"Warning: could not load {mod_name}: {e}")
        return suite

    if not feature_filter:
        return loaded

    # Filter tests matching feature_filter (e.g. 'F1', 'F8')
    norm_filter = feature_filter.upper()
    filtered_suite = unittest.TestSuite()

    def filter_tests(item):
        if isinstance(item, unittest.TestSuite):
            for sub in item:
                filter_tests(sub)
        elif isinstance(item, unittest.TestCase):
            name = item.id().upper()
            if f"_{norm_filter}_" in name or f"_{norm_filter}" in name or f"{norm_filter}_" in name:
                filtered_suite.addTest(item)

    filter_tests(loaded)
    return filtered_suite


def run_e2e_suite(
    tiers: list[int],
    feature_filter: str = "",
    verbosity: int = 1,
    failfast: bool = False
) -> int:
    """Executes the test suite across selected tiers and outputs a comprehensive summary."""
    print(ColoredText.colorize("=" * 80, ColoredText.BOLD))
    print(ColoredText.colorize("  Cloudflare Clean IP Scanner (cf-tester) - 4-Tier E2E Test Suite", ColoredText.BOLD + ColoredText.CYAN))
    print(ColoredText.colorize("=" * 80, ColoredText.BOLD))
    print(f"Running Tiers: {tiers}")
    if feature_filter:
        print(f"Feature Filter: {feature_filter.upper()}")
    print("-" * 80)

    overall_start = time.perf_counter()
    tier_summaries = {}
    has_failure = False

    for t in tiers:
        suite = load_tier_suite(t, feature_filter)
        total_tests = suite.countTestCases()
        if total_tests == 0:
            tier_summaries[t] = {"total": 0, "passed": 0, "skipped": 0, "failed": 0, "errors": 0, "duration": 0.0}
            continue

        print(f"\n>> Executing Tier {t} ({total_tests} test cases)...")
        tracker = TierResultTracker()
        runner = unittest.TextTestRunner(
            verbosity=verbosity,
            failfast=failfast,
            resultclass=TierResultTracker
        )
        t_start = time.perf_counter()
        res = runner.run(suite)
        t_dur = time.perf_counter() - t_start

        passed_count = len(getattr(res, "successes", []))
        skipped_count = len(res.skipped)
        failed_count = len(res.failures)
        errors_count = len(res.errors)

        tier_summaries[t] = {
            "total": total_tests,
            "passed": passed_count,
            "skipped": skipped_count,
            "failed": failed_count,
            "errors": errors_count,
            "duration": t_dur,
        }

        if failed_count > 0 or errors_count > 0:
            has_failure = True

    overall_dur = time.perf_counter() - overall_start

    # Print Summary Table
    print("\n" + ColoredText.colorize("=" * 80, ColoredText.BOLD))
    print(ColoredText.colorize("                     E2E TEST SUITE EXECUTION SUMMARY", ColoredText.BOLD))
    print(ColoredText.colorize("=" * 80, ColoredText.BOLD))
    print(f"{'Tier':<25} | {'Total':<7} | {'Passed':<7} | {'Skipped':<8} | {'Failed':<7} | {'Time (s)':<8}")
    print("-" * 80)

    tier_names = {
        1: "Tier 1: Feature Coverage",
        2: "Tier 2: Boundary & Corner",
        3: "Tier 3: Combinations",
        4: "Tier 4: Real-World Scenarios",
    }

    grand_total = 0
    grand_passed = 0
    grand_skipped = 0
    grand_failed = 0
    grand_errors = 0

    for t in tiers:
        s = tier_summaries.get(t, {"total": 0, "passed": 0, "skipped": 0, "failed": 0, "errors": 0, "duration": 0.0})
        grand_total += s["total"]
        grand_passed += s["passed"]
        grand_skipped += s["skipped"]
        grand_failed += s["failed"]
        grand_errors += s["errors"]

        name = tier_names.get(t, f"Tier {t}")
        pass_str = ColoredText.colorize(str(s["passed"]), ColoredText.GREEN if s["passed"] > 0 else "")
        skip_str = ColoredText.colorize(str(s["skipped"]), ColoredText.YELLOW if s["skipped"] > 0 else "")
        fail_val = s["failed"] + s["errors"]
        fail_str = ColoredText.colorize(str(fail_val), ColoredText.RED if fail_val > 0 else "")

        print(f"{name:<25} | {s['total']:<7} | {pass_str:<16} | {skip_str:<17} | {fail_str:<16} | {s['duration']:<8.2f}")

    print("-" * 80)
    total_failures = grand_failed + grand_errors
    res_badge = ColoredText.colorize("SUCCESS (0 ERRORS)", ColoredText.GREEN + ColoredText.BOLD) if not has_failure else ColoredText.colorize("FAILED", ColoredText.RED + ColoredText.BOLD)
    print(f"{'GRAND TOTAL':<25} | {grand_total:<7} | {grand_passed:<7} | {grand_skipped:<8} | {total_failures:<7} | {overall_dur:<8.2f}")
    print(ColoredText.colorize("=" * 80, ColoredText.BOLD))
    print(f"Overall Result: {res_badge} in {overall_dur:.2f}s\n")

    return 1 if has_failure else 0


def main():
    parser = argparse.ArgumentParser(description="Automated E2E Test Runner for Cloudflare Clean IP Scanner")
    parser.add_argument("--tier", type=int, choices=[1, 2, 3, 4], help="Run a specific test tier (1, 2, 3, or 4)")
    parser.add_argument("--feature", type=str, default="", help="Filter tests by Feature ID (e.g. F1, F3, F8)")
    parser.add_argument("-v", "--verbose", action="count", default=1, help="Increase output verbosity")
    parser.add_argument("-f", "--failfast", action="store_true", help="Stop on first failure or error")

    args = parser.parse_args()

    tiers = [args.tier] if args.tier else [1, 2, 3, 4]
    exit_code = run_e2e_suite(
        tiers=tiers,
        feature_filter=args.feature,
        verbosity=args.verbose,
        failfast=args.failfast,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
