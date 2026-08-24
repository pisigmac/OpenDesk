#!/usr/bin/env bash
# ==============================================================================
# OpenDesk Auth — End-to-End Test Utility (curl-based)
# ==============================================================================
# This script starts the OpenDesk Auth server on a test port, executes an
# end-to-end suite of curl commands against all core endpoints, and shuts down
# the server process on completion (or on failure/SIGINT).
# ==============================================================================

set -euo pipefail

# Configuration
TEST_PORT="${AUTH_PORT:-8099}"
TEST_HOST="${AUTH_HOST:-127.0.0.1}"
BASE_URL="http://${TEST_HOST}:${TEST_PORT}"
TMP_DIR="$(mktemp -d /tmp/opendesk_e2e.XXXXXX)"
DB_PATH="${TMP_DIR}/test.db"
KEY_PRIV="${TMP_DIR}/private.pem"
KEY_PUB="${TMP_DIR}/public.pem"
BOOTSTRAP_TOKEN="e2e-bootstrap-secret-key-12345"
INTROSPECT_KEY="e2e-introspect-secret-key"

SERVER_PID=""

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

# Cleanup handler
cleanup() {
    echo -e "\n${YELLOW}=== Tearing down OpenDesk Auth test environment ===${NC}"
    if [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        echo "Stopping OpenDesk Auth server (PID: ${SERVER_PID})..."
        kill "${SERVER_PID}" || true
        wait "${SERVER_PID}" 2>/dev/null || true
        echo "Server stopped."
    fi
    if [ -d "${TMP_DIR}" ]; then
        rm -rf "${TMP_DIR}"
        echo "Cleaned up temporary directory: ${TMP_DIR}"
    fi
    echo -e "${GREEN}Teardown complete.${NC}"
}

trap cleanup EXIT INT TERM

log_step() {
    echo -e "\n${BLUE}${BOLD}[TEST STEP]${NC} $1"
}

assert_status() {
    local expected="$1"
    local actual="$2"
    local step_name="$3"
    if [ "${actual}" -eq "${expected}" ]; then
        echo -e "  ${GREEN}✓ PASS:${NC} ${step_name} (HTTP ${actual})"
    else
        echo -e "  ${RED}✗ FAIL:${NC} ${step_name} (Expected HTTP ${expected}, got HTTP ${actual})"
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# 1. Setup Keys and Environment
# ------------------------------------------------------------------------------
echo -e "${BOLD}=====================================================${NC}"
echo -e "${BOLD}    OpenDesk Auth — End-to-End Curl Test Utility    ${NC}"
echo -e "${BOLD}=====================================================${NC}"

log_step "Generating temporary RSA keypair for JWT signing..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${KEY_PRIV}" 2>/dev/null
openssl rsa -in "${KEY_PRIV}" -pubout -out "${KEY_PUB}" 2>/dev/null

log_step "Starting OpenDesk Auth server on ${BASE_URL}..."
export AUTH_DATABASE_URL="sqlite+pysqlite:///${DB_PATH}"
export AUTH_ISSUER="https://auth.opendesk.local"
export AUTH_HOST="${TEST_HOST}"
export AUTH_PORT="${TEST_PORT}"
export AUTH_OPEN_REGISTRATION="false"
export AUTH_BOOTSTRAP_TOKEN="${BOOTSTRAP_TOKEN}"
export AUTH_REQUIRE_EMAIL_VERIFICATION="false"
export AUTH_INTROSPECTION_API_KEY="${INTROSPECT_KEY}"
export AUTH_JWT_PRIVATE_KEY_FILE="${KEY_PRIV}"
export AUTH_JWT_PUBLIC_KEY_FILE="${KEY_PUB}"
export PYTHONPATH="src"

python3 -m opendesk_auth.cli > "${TMP_DIR}/server.log" 2>&1 &
SERVER_PID=$!

echo "Server started with PID ${SERVER_PID}. Waiting for server readiness..."

# Poll /health until up (max 10s)
READY=0
for i in {1..20}; do
    if curl -s "${BASE_URL}/health" | grep -q '"status"' 2>/dev/null; then
        READY=1
        break
    fi
    sleep 0.5
done

if [ "${READY}" -ne 1 ]; then
    echo -e "${RED}Server failed to start within 10 seconds. Log output:${NC}"
    cat "${TMP_DIR}/server.log"
    exit 1
fi

echo -e "${GREEN}Server is up and healthy!${NC}"

# ------------------------------------------------------------------------------
# 2. Health, Landing Page & JWKS Endpoints
# ------------------------------------------------------------------------------
log_step "Testing GET / (Production Landing Page)..."
LANDING_RES=$(curl -s -w "\n%{http_code}" "${BASE_URL}/")
LANDING_CODE=$(echo "${LANDING_RES}" | tail -n1)
assert_status 200 "${LANDING_CODE}" "GET / (Landing Page)"

log_step "Testing GET /health..."
HEALTH_RES=$(curl -s -w "\n%{http_code}" "${BASE_URL}/health")
HEALTH_BODY=$(echo "${HEALTH_RES}" | head -n1)
HEALTH_CODE=$(echo "${HEALTH_RES}" | tail -n1)
assert_status 200 "${HEALTH_CODE}" "GET /health"
echo "  Response: ${HEALTH_BODY}"

log_step "Testing GET /.well-known/jwks.json..."
JWKS_RES=$(curl -s -w "\n%{http_code}" "${BASE_URL}/.well-known/jwks.json")
JWKS_BODY=$(echo "${JWKS_RES}" | head -n1)
JWKS_CODE=$(echo "${JWKS_RES}" | tail -n1)
assert_status 200 "${JWKS_CODE}" "GET /.well-known/jwks.json"
echo "  Keys found: $(echo "${JWKS_BODY}" | jq -r '.keys[0].kid')"

log_step "Testing GET /admin/console..."
CONSOLE_RES=$(curl -s -w "\n%{http_code}" "${BASE_URL}/admin/console")
CONSOLE_CODE=$(echo "${CONSOLE_RES}" | tail -n1)
assert_status 200 "${CONSOLE_CODE}" "GET /admin/console"

# ------------------------------------------------------------------------------
# 3. User Registration & Authentication Flow
# ------------------------------------------------------------------------------
log_step "Testing POST /v1/auth/register (First Admin with Bootstrap Token)..."
ADMIN_EMAIL="admin@example.com"
ADMIN_PASS="AdminSecret123!"

REG_RES=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/v1/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"${ADMIN_EMAIL}\", \"password\": \"${ADMIN_PASS}\", \"display_name\": \"Admin User\", \"bootstrap_token\": \"${BOOTSTRAP_TOKEN}\"}")

REG_BODY=$(echo "${REG_RES}" | head -n1)
REG_CODE=$(echo "${REG_RES}" | tail -n1)
assert_status 200 "${REG_CODE}" "POST /v1/auth/register"

ACCESS_TOKEN=$(echo "${REG_BODY}" | jq -r '.access_token')
REFRESH_TOKEN=$(echo "${REG_BODY}" | jq -r '.refresh_token')
echo "  Access Token issued: ${ACCESS_TOKEN:0:30}..."

log_step "Testing POST /v1/auth/login..."
LOGIN_RES=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"${ADMIN_EMAIL}\", \"password\": \"${ADMIN_PASS}\"}")

LOGIN_BODY=$(echo "${LOGIN_RES}" | head -n1)
LOGIN_CODE=$(echo "${LOGIN_RES}" | tail -n1)
assert_status 200 "${LOGIN_CODE}" "POST /v1/auth/login"

log_step "Testing GET /v1/auth/me (Authenticated User Profile)..."
ME_RES=$(curl -s -w "\n%{http_code}" -X GET "${BASE_URL}/v1/auth/me" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}")

ME_BODY=$(echo "${ME_RES}" | head -n1)
ME_CODE=$(echo "${ME_RES}" | tail -n1)
assert_status 200 "${ME_CODE}" "GET /v1/auth/me"
ADMIN_ID=$(echo "${ME_BODY}" | jq -r '.id')
echo "  User ID: ${ADMIN_ID}, Email: $(echo "${ME_BODY}" | jq -r '.email'), Platform Admin: $(echo "${ME_BODY}" | jq -r '.is_platform_admin')"

# ------------------------------------------------------------------------------
# 4. Token Refresh Flow
# ------------------------------------------------------------------------------
log_step "Testing POST /v1/auth/refresh..."
REFRESH_RES=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/v1/auth/refresh" \
    -H "Content-Type: application/json" \
    -d "{\"refresh_token\": \"${REFRESH_TOKEN}\"}")

REFRESH_BODY=$(echo "${REFRESH_RES}" | head -n1)
REFRESH_CODE=$(echo "${REFRESH_RES}" | tail -n1)
assert_status 200 "${REFRESH_CODE}" "POST /v1/auth/refresh"

NEW_ACCESS_TOKEN=$(echo "${REFRESH_BODY}" | jq -r '.access_token')
NEW_REFRESH_TOKEN=$(echo "${REFRESH_BODY}" | jq -r '.refresh_token')
echo "  New Access Token: ${NEW_ACCESS_TOKEN:0:30}..."

# ------------------------------------------------------------------------------
# 5. Organizations & Tenancy
# ------------------------------------------------------------------------------
log_step "Testing POST /v1/orgs (Create Org)..."
ORG_RES=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/v1/orgs" \
    -H "Authorization: Bearer ${NEW_ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"OpenDesk Engineering\"}")

ORG_BODY=$(echo "${ORG_RES}" | head -n1)
ORG_CODE=$(echo "${ORG_RES}" | tail -n1)
assert_status 200 "${ORG_CODE}" "POST /v1/orgs"
ORG_ID=$(echo "${ORG_BODY}" | jq -r '.id')
echo "  Org Created: ID=${ORG_ID}, Name=$(echo "${ORG_BODY}" | jq -r '.name')"

log_step "Testing GET /v1/orgs (List User Orgs)..."
LIST_ORGS_RES=$(curl -s -w "\n%{http_code}" -X GET "${BASE_URL}/v1/orgs" \
    -H "Authorization: Bearer ${NEW_ACCESS_TOKEN}")

LIST_ORGS_CODE=$(echo "${LIST_ORGS_RES}" | tail -n1)
assert_status 200 "${LIST_ORGS_CODE}" "GET /v1/orgs"

# ------------------------------------------------------------------------------
# 6. Admin API & Grants
# ------------------------------------------------------------------------------
log_step "Testing POST /v1/admin/grants (Set Product Grant)..."
GRANT_RES=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/v1/admin/grants" \
    -H "Authorization: Bearer ${NEW_ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"user_id\": \"${ADMIN_ID}\", \"audience\": \"opendesk-analytics\", \"role\": \"admin\"}")

GRANT_CODE=$(echo "${GRANT_RES}" | tail -n1)
assert_status 200 "${GRANT_CODE}" "POST /v1/admin/grants"

log_step "Testing GET /v1/admin/users (List Platform Users)..."
USERS_RES=$(curl -s -w "\n%{http_code}" -X GET "${BASE_URL}/v1/admin/users" \
    -H "Authorization: Bearer ${NEW_ACCESS_TOKEN}")

USERS_BODY=$(echo "${USERS_RES}" | head -n1)
USERS_CODE=$(echo "${USERS_RES}" | tail -n1)
assert_status 200 "${USERS_CODE}" "GET /v1/admin/users"
echo "  Total Platform Users: $(echo "${USERS_BODY}" | jq -r '.total')"

log_step "Testing GET /v1/admin/audit (Query Audit Log)..."
AUDIT_RES=$(curl -s -w "\n%{http_code}" -X GET "${BASE_URL}/v1/admin/audit" \
    -H "Authorization: Bearer ${NEW_ACCESS_TOKEN}")

AUDIT_BODY=$(echo "${AUDIT_RES}" | head -n1)
AUDIT_CODE=$(echo "${AUDIT_RES}" | tail -n1)
assert_status 200 "${AUDIT_CODE}" "GET /v1/admin/audit"
echo "  Total Audit Log Events Recorded: $(echo "${AUDIT_BODY}" | jq -r '.total')"

# ------------------------------------------------------------------------------
# 7. Introspection Endpoint
# ------------------------------------------------------------------------------
log_step "Testing POST /introspect (Token Introspection)..."
INTROSPECT_RES=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/introspect" \
    -H "Authorization: Bearer ${INTROSPECT_KEY}" \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"${NEW_ACCESS_TOKEN}\"}")

INTROSPECT_BODY=$(echo "${INTROSPECT_RES}" | head -n1)
INTROSPECT_CODE=$(echo "${INTROSPECT_RES}" | tail -n1)
assert_status 200 "${INTROSPECT_CODE}" "POST /introspect"
echo "  Token Active: $(echo "${INTROSPECT_BODY}" | jq -r '.active'), Subject: $(echo "${INTROSPECT_BODY}" | jq -r '.claims.sub')"

# ------------------------------------------------------------------------------
# 8. User Data Export & Logout
# ------------------------------------------------------------------------------
log_step "Testing GET /v1/me/export (GDPR Data Export)..."
EXPORT_RES=$(curl -s -w "\n%{http_code}" -X GET "${BASE_URL}/v1/me/export" \
    -H "Authorization: Bearer ${NEW_ACCESS_TOKEN}")

EXPORT_CODE=$(echo "${EXPORT_RES}" | tail -n1)
assert_status 200 "${EXPORT_CODE}" "GET /v1/me/export"

log_step "Testing POST /v1/auth/logout..."
LOGOUT_RES=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/v1/auth/logout" \
    -H "Content-Type: application/json" \
    -d "{\"refresh_token\": \"${NEW_REFRESH_TOKEN}\"}")

LOGOUT_CODE=$(echo "${LOGOUT_RES}" | tail -n1)
assert_status 200 "${LOGOUT_CODE}" "POST /v1/auth/logout"

# ------------------------------------------------------------------------------
# End of Test Suite
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}${GREEN}=====================================================${NC}"
echo -e "${BOLD}${GREEN}   All End-to-End Curl Tests Passed Successfully!   ${NC}"
echo -e "${BOLD}${GREEN}=====================================================${NC}"
