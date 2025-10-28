#!/usr/bin/env bash
#
# Self-test for linux-vulnscan.sh
# Run: ./tests/selftest.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/../linux-vulnscan.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log_info() {
    log "${GREEN}INFO${NC}: $*"
}

log_warn() {
    log "${YELLOW}WARN${NC}: $*"
}

log_error() {
    log "${RED}ERROR${NC}: $*"
}

run_test() {
    local test_name="$1"
    local command="$2"
    
    log_info "Running test: $test_name"
    
    if eval "$command"; then
        log_info "✅ Test passed: $test_name"
        return 0
    else
        log_error "❌ Test failed: $test_name"
        return 1
    fi
}

# Test cases
test_script_exists() {
    [ -f "$SCRIPT_PATH" ] && [ -x "$SCRIPT_PATH" ]
}

test_help_command() {
    "$SCRIPT_PATH" --help 2>&1 | grep -q "USAGE:"
}

test_dry_run() {
    "$SCRIPT_PATH" --dry-run --quiet 2>&1 | grep -q "Dry run mode"
}

test_selftest_mode() {
    "$SCRIPT_PATH" --selftest --quiet
}

test_json_output() {
    local output_file="/tmp/test-scan-$$.json"
    "$SCRIPT_PATH" --dry-run --output-json "$output_file" --quiet
    
    if [ -f "$output_file" ]; then
        # Validate JSON structure
        python3 -c "
import json, sys
try:
    with open('$output_file') as f:
        data = json.load(f)
    required = ['scan_id', 'timestamp', 'host', 'scanner_results']
    if all(field in data for field in required):
        sys.exit(0)
    else:
        sys.exit(1)
except Exception as e:
    sys.exit(1)
        "
        local result=$?
        rm -f "$output_file"
        return $result
    else
        return 1
    fi
}

test_ci_mode() {
    # Test that CI mode doesn't fail without vulnerabilities
    "$SCRIPT_PATH" --dry-run --ci --quiet
}

# Main test execution
main() {
    log_info "Starting self-tests for linux-vulnscan.sh"
    
    local tests_passed=0
    local tests_failed=0
    
    # Run test cases
    run_test "Script exists and executable" "test_script_exists" && ((tests_passed++)) || ((tests_failed++))
    run_test "Help command works" "test_help_command" && ((tests_passed++)) || ((tests_failed++))
    run_test "Dry run mode works" "test_dry_run" && ((tests_passed++)) || ((tests_failed++))
    run_test "Self-test mode works" "test_selftest_mode" && ((tests_passed++)) || ((tests_failed++))
    run_test "JSON output generation" "test_json_output" && ((tests_passed++)) || ((tests_failed++))
    run_test "CI mode execution" "test_ci_mode" && ((tests_passed++)) || ((tests_failed++))
    
    # Summary
    log_info "Test results: $tests_passed passed, $tests_failed failed"
    
    if [ "$tests_failed" -eq 0 ]; then
        log_info "✅ All tests passed!"
        exit 0
    else
        log_error "❌ Some tests failed!"
        exit 1
    fi
}

# Run main if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi
