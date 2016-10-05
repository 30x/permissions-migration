export IPADDRESS="127.0.0.1"
export PORT=3007
export COMPONENT="permissions-migration"
export SPEEDUP=10
export EXTERNAL_ROUTER="localhost:8080"
export INTERNAL_ROUTER="localhost:8080"
export EDGE_HOST="api.e2e.apigee.net"
export CLIENT_ID=${CLIENT_ID:-defaultclient} # configure this in your shell when testing
export CLIENT_SECRET=${CLIENT_SECRET:-defaultsecret} # configure this in your shell when testing

node permissions-migration.js