# Scoped identity used by AppRole / Userpass / JWT / Kubernetes logins in the SDK tests.
# Allowed: everything under sdk/allowed/ in both KV mounts. Anything else -> 403.
path "secret/data/sdk/allowed/*"     { capabilities = ["create", "read", "update", "patch", "delete"] }
path "secret/metadata/sdk/allowed/*" { capabilities = ["read", "list", "delete"] }
path "secret/metadata/sdk/allowed"   { capabilities = ["list"] }
path "kv1/sdk/allowed/*"             { capabilities = ["create", "read", "update", "delete", "list"] }
path "kv1/sdk/allowed"               { capabilities = ["list"] }
# Mount auto-detection for restricted tokens.
path "sys/internal/ui/mounts/*"      { capabilities = ["read"] }
