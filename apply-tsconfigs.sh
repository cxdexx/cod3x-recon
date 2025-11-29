#!/bin/bash
set -e

echo "🚀 COD3X:RECON - Pre-Release Verification"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

FAILED=0

run_test() {
    echo -n "Testing: $1... "
    if eval "$2" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        FAILED=$((FAILED+1))
    fi
}

# # Clean build
# echo "🧹 Clean build test..."
# rm -rf dist node_modules
# npm install --silent
# npm run build --silent
# echo -e "${GREEN}✓ Clean build successful${NC}\n"

# # Unit tests
# echo "🧪 Running unit tests..."
# npm test -- --reporter=dot
# echo -e "${GREEN}✓ All tests passed${NC}\n"

# # Lint
# echo "🔍 Running linter..."
# npm run lint
# echo -e "${GREEN}✓ Lint clean${NC}\n"

# # Format check
# echo "✨ Checking formatting..."
# npx prettier --check "src/**/*.ts" "tests/**/*.ts"
# echo -e "${GREEN}✓ Format clean${NC}\n"

# CLI smoke test
echo "💨 CLI smoke test..."
run_test "Help command" "node dist/cli/index.js --help"
run_test "Version command" "node dist/cli/index.js --version"
run_test "Scan help" "node dist/cli/index.js scan --help"

# # Live test
# echo ""
# echo "🌐 Live scan test (github.com)..."
# npm start -- scan -d github.com --concurrency 5 --quiet
# echo -e "${GREEN}✓ Live scan successful${NC}\n"

# # JSON export test
# echo "📄 JSON export test..."
# npm start -- scan -d github.com --format json --export test-output.json --concurrency 5 --quiet
# cat test-output.json | jq . > /dev/null
# rm -f test-output.json
# echo -e "${GREEN}✓ JSON export works${NC}\n"

# Security checks
echo "🔒 Security checks..."
run_test "No secrets in code" "! grep -r 'api_key\|password\s*=' src/"
run_test "No .env in repo" "! git ls-files | grep '\.env'"
run_test "Input validation" "npm start -- scan -d 'invalid!@#' --quiet 2>&1 | grep -q 'Invalid domain'"

echo ""
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✅ ALL CHECKS PASSED - READY TO RELEASE  ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${RED}╔════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ❌ $FAILED CHECKS FAILED - DO NOT RELEASE  ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════╝${NC}"
    exit 1
fi