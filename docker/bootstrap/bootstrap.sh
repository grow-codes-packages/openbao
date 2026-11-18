#!/bin/sh
# One-shot, idempotent bootstrap of the OpenBao SDK test fixture.
# Runs in the openbao/openbao image (bao CLI, busybox sh/sed/wget; no curl/jq).
# Writes KEY=value lines to /bootstrap/env. All values are TEST-ONLY.
set -eu
umask 022

SCRIPTS=/bootstrap-scripts
ENV_FILE=/bootstrap/env
STATE=/bootstrap/.state
mkdir -p "$STATE"
chmod 700 "$STATE"

log() { printf 'bootstrap: %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# --- 1. wait until the server answers (bao status: 0 unsealed, 2 sealed, 1 error) ---
i=0
until bao status >/dev/null 2>&1; [ $? -ne 1 ]; do
  i=$((i + 1)); [ "$i" -lt 120 ] || die "OpenBao at $BAO_ADDR never answered"
  sleep 1
done

# --- 2. initialise once (static seal => recovery keys, auto-unsealed) ---
if bao status -format=json 2>/dev/null | grep -q '"initialized": *false'; then
  log "initialising $BAO_ADDR (static seal, 1 recovery share)"
  bao operator init -recovery-shares=1 -recovery-threshold=1 -format=json > "$STATE/init.json"
  chmod 600 "$STATE/init.json"
fi
[ -f "$STATE/init.json" ] || die "OpenBao is initialised but $STATE/init.json is missing (volume lost?) - recreate the stack with down -v"
ROOT_TOKEN="$(tr -d '\n' < "$STATE/init.json" | sed -n 's/.*"root_token": *"\([^"]*\)".*/\1/p')"
[ -n "$ROOT_TOKEN" ] || die "no root_token in init.json"
export BAO_TOKEN="$ROOT_TOKEN"

# --- 3. wait for active + unsealed (sys/health 200 only when active) ---
i=0
# (429 = standby is seen for ~1 s right after init while Raft elects itself)
until wget -q -O /dev/null "$BAO_ADDR/v1/sys/health" 2>/dev/null; do
  i=$((i + 1)); [ "$i" -lt 120 ] || die "OpenBao never became active"
  sleep 1
done
until bao token lookup >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 180 ] || die "root token not usable"
  sleep 1
done

# KV v2 mounts answer 400 "Upgrading from non-versioned to versioned data" for a moment
# after being enabled; retry writes.
retry() { n=0; until "$@" 2>/dev/null; do n=$((n + 1)); [ "$n" -lt 30 ] || { "$@"; return 1; }; sleep 1; done; }

has_mount() { bao secrets list -format=json | grep -q "\"$1/\""; }
has_auth()  { bao auth list -format=json | grep -q "\"$1/\""; }

# --- 4. secrets engines ---
has_mount kv1      || bao secrets enable -path=kv1 -version=1 -description="SDK KV v1" kv >/dev/null
has_mount secret   || bao secrets enable -path=secret -version=2 -description="SDK KV v2" kv >/dev/null
has_mount transit  || bao secrets enable -path=transit transit >/dev/null
has_mount database || bao secrets enable -path=database database >/dev/null
has_mount pki      || bao secrets enable -path=pki -max-lease-ttl=87600h pki >/dev/null

# --- 5. auth methods ---
has_auth approle    || bao auth enable -path=approle approle >/dev/null
has_auth userpass   || bao auth enable -path=userpass userpass >/dev/null
has_auth jwt        || bao auth enable -path=jwt jwt >/dev/null
has_auth kubernetes || bao auth enable -path=kubernetes kubernetes >/dev/null

# --- 6. policy for the scoped identities ---
bao policy write sdk-app "$SCRIPTS/policies/sdk-app.hcl" >/dev/null

# AppRole: unlimited-use secret id so several suites can log in.
bao write auth/approle/role/sdk-app token_policies=sdk-app token_ttl=1h token_max_ttl=4h \
  secret_id_ttl=0 secret_id_num_uses=0 >/dev/null
APPROLE_ROLE_ID="$(bao read -field=role_id auth/approle/role/sdk-app/role-id)"
if [ ! -s "$STATE/approle-secret-id" ]; then
  bao write -f -field=secret_id auth/approle/role/sdk-app/secret-id > "$STATE/approle-secret-id"
fi
APPROLE_SECRET_ID="$(cat "$STATE/approle-secret-id")"

# Userpass.
USERPASS_PASSWORD=sdk-user-test-only-password
bao write auth/userpass/users/sdk-user password="$USERPASS_PASSWORD" token_policies=sdk-app \
  token_ttl=1h token_max_ttl=4h >/dev/null

# JWT with a static test key (no OIDC discovery / JWKS).
bao write auth/jwt/config jwt_validation_pubkeys=@"$SCRIPTS/jwt/test-only-signing-key.pub.pem" \
  bound_issuer=https://jwt.grow-sdk.test >/dev/null
bao write auth/jwt/role/sdk-jwt role_type=jwt user_claim=sub bound_subject=sdk-jwt-user \
  bound_audiences=grow-sdk-tests token_policies=sdk-app token_ttl=1h >/dev/null
JWT="$(tr -d '\n' < "$SCRIPTS/jwt/test-only.jwt")"
JWT_EXPIRED="$(tr -d '\n' < "$SCRIPTS/jwt/test-only-expired.jwt")"
K8S_JWT="$(tr -d '\n' < "$SCRIPTS/jwt/test-only-k8s-sa.jwt")"


# --- 7. transit keys ---
bao read transit/keys/sdk-aes  >/dev/null 2>&1 || bao write -f transit/keys/sdk-aes type=aes256-gcm96 >/dev/null
bao read transit/keys/sdk-sign >/dev/null 2>&1 || bao write -f transit/keys/sdk-sign type=ed25519 >/dev/null
bao read transit/keys/sdk-rsa  >/dev/null 2>&1 || bao write -f transit/keys/sdk-rsa type=rsa-2048 >/dev/null

# --- 8. database engine -> PostgreSQL sidecar ---
bao write database/config/sdk-postgres plugin_name=postgresql-database-plugin \
  connection_url="postgresql://{{username}}:{{password}}@${PG_HOST}:${PG_PORT}/${PG_DB}?sslmode=disable" \
  username="$PG_ADMIN_USER" password="$PG_ADMIN_PASSWORD" allowed_roles="*" >/dev/null
RO_SQL="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
bao write database/roles/sdk-readonly db_name=sdk-postgres creation_statements="$RO_SQL" \
  default_ttl=1h max_ttl=24h >/dev/null
bao write database/roles/sdk-short db_name=sdk-postgres creation_statements="$RO_SQL" \
  default_ttl=10s max_ttl=30s >/dev/null

# --- 9. PKI: ephemeral root CA + test role ---
if ! bao read pki/cert/ca >/dev/null 2>&1 || [ -z "$(bao read -field=certificate pki/cert/ca 2>/dev/null)" ]; then
  bao write pki/root/generate/internal common_name="Grow SDK Test Root CA" issuer_name=sdk-root \
    key_type=ec key_bits=256 ttl=87600h >/dev/null 2>&1
fi
bao write pki/roles/sdk-test allowed_domains=example.test allow_subdomains=true allow_bare_domains=true \
  key_type=ec key_bits=256 max_ttl=72h ttl=24h >/dev/null

# Kubernetes auth: configured so the login request shape can be exercised; the
# TokenReview call cannot succeed without a real Kubernetes API (documented).
# Any PEM CA is accepted for the config; reuse the test PKI root.
bao read -field=certificate pki/cert/ca > "$STATE/k8s-ca.pem"
bao write auth/kubernetes/config kubernetes_host=https://kubernetes.invalid:6443 \
  kubernetes_ca_cert=@"$STATE/k8s-ca.pem" disable_local_ca_jwt=true >/dev/null
bao write auth/kubernetes/role/sdk-k8s bound_service_account_names=sdk \
  bound_service_account_namespaces=default token_policies=sdk-app token_ttl=1h >/dev/null

# --- 10. seed KV data ---
retry env bao kv put -mount=secret sdk/allowed/hello value=world >/dev/null
retry env bao kv put -mount=secret sdk/denied/hello value=hidden >/dev/null
retry env bao kv put -mount=kv1 sdk/allowed/hello value=world >/dev/null
retry env bao kv put -mount=kv1 sdk/denied/hello value=hidden >/dev/null
bao kv get -mount=secret sdk/sentinel >/dev/null 2>&1 || retry bao kv put -mount=secret sdk/sentinel value=survives-restart >/dev/null

# --- 11. namespace (X-Vault-Namespace) ---
NAMESPACE=""
if bao namespace lookup sdk-ns >/dev/null 2>&1 || bao namespace create sdk-ns >/dev/null 2>&1; then
  NAMESPACE=sdk-ns
  BAO_NAMESPACE=sdk-ns bao secrets list -format=json | grep -q '"secret/"' \
    || BAO_NAMESPACE=sdk-ns bao secrets enable -path=secret -version=2 kv >/dev/null
  retry env BAO_NAMESPACE=sdk-ns bao kv put -mount=secret sdk/in-namespace value=ns-only >/dev/null
else
  log "namespaces not available - GROW_OPENBAO_TEST_NAMESPACE left empty"
fi

VERSION="$(bao status -format=json | sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' | head -n1)"

# --- 12. write /bootstrap/env atomically ---
TMP="$ENV_FILE.tmp.$$"
cat > "$TMP" <<EOF
GROW_OPENBAO_URL=http://openbao:8200
GROW_OPENBAO_TOKEN=$ROOT_TOKEN
GROW_OPENBAO_TEST_SERVER_VERSION=$VERSION
GROW_OPENBAO_TEST_SHAMIR_URL=http://openbao-shamir:8200
GROW_OPENBAO_TEST_NAMESPACE=$NAMESPACE
GROW_OPENBAO_TEST_KV1_MOUNT=kv1
GROW_OPENBAO_TEST_KV2_MOUNT=secret
GROW_OPENBAO_TEST_ALLOWED_PATH=sdk/allowed/hello
GROW_OPENBAO_TEST_DENIED_PATH=sdk/denied/hello
GROW_OPENBAO_TEST_SENTINEL_PATH=sdk/sentinel
GROW_OPENBAO_TEST_POLICY=sdk-app
GROW_OPENBAO_TEST_TRANSIT_MOUNT=transit
GROW_OPENBAO_TEST_TRANSIT_AES_KEY=sdk-aes
GROW_OPENBAO_TEST_TRANSIT_SIGN_KEY=sdk-sign
GROW_OPENBAO_TEST_TRANSIT_RSA_KEY=sdk-rsa
GROW_OPENBAO_TEST_DB_MOUNT=database
GROW_OPENBAO_TEST_DB_CONNECTION=sdk-postgres
GROW_OPENBAO_TEST_DB_ROLE=sdk-readonly
GROW_OPENBAO_TEST_DB_SHORT_ROLE=sdk-short
GROW_OPENBAO_TEST_PG_HOST=$PG_HOST
GROW_OPENBAO_TEST_PG_PORT=$PG_PORT
GROW_OPENBAO_TEST_PG_DB=$PG_DB
GROW_OPENBAO_TEST_PG_ADMIN_USER=$PG_ADMIN_USER
GROW_OPENBAO_TEST_PG_ADMIN_PASSWORD=$PG_ADMIN_PASSWORD
GROW_OPENBAO_TEST_PKI_MOUNT=pki
GROW_OPENBAO_TEST_PKI_ROLE=sdk-test
GROW_OPENBAO_TEST_PKI_DOMAIN=example.test
GROW_OPENBAO_TEST_APPROLE_MOUNT=approle
GROW_OPENBAO_TEST_APPROLE_ROLE=sdk-app
GROW_OPENBAO_TEST_APPROLE_ROLE_ID=$APPROLE_ROLE_ID
GROW_OPENBAO_TEST_APPROLE_SECRET_ID=$APPROLE_SECRET_ID
GROW_OPENBAO_TEST_USERPASS_MOUNT=userpass
GROW_OPENBAO_TEST_USERPASS_USER=sdk-user
GROW_OPENBAO_TEST_USERPASS_PASSWORD=$USERPASS_PASSWORD
GROW_OPENBAO_TEST_JWT_MOUNT=jwt
GROW_OPENBAO_TEST_JWT_ROLE=sdk-jwt
GROW_OPENBAO_TEST_JWT=$JWT
GROW_OPENBAO_TEST_JWT_EXPIRED=$JWT_EXPIRED
GROW_OPENBAO_TEST_K8S_MOUNT=kubernetes
GROW_OPENBAO_TEST_K8S_ROLE=sdk-k8s
GROW_OPENBAO_TEST_K8S_JWT=$K8S_JWT
EOF
chmod 644 "$TMP"
mv "$TMP" "$ENV_FILE"
log "done (OpenBao $VERSION); wrote $(wc -l < "$ENV_FILE") lines to $ENV_FILE"
