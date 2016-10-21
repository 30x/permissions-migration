export IPADDRESS="127.0.0.1"
export PORT=3007
export COMPONENT="permissions-migration"
export SPEEDUP=10
export EXTERNAL_ROUTER_HOST="localhost"
export EXTERNAL_ROUTER_PORT="8080"
export INTERNAL_ROUTER_HOST="localhost"
export INTERNAL_ROUTER_PORT="8080"
export EDGE_ADDRESS="https://api.e2e.apigee.net"
export PERMISSIONS_MIGRATION_CLIENTID=${PERMISSIONS_MIGRATION_CLIENTID:-defaultclient} # configure this in your shell when testing
export PERMISSIONS_MIGRATION_CLIENTSECRET=${PERMISSIONS_MIGRATION_CLIENTSECRET:-defaultsecret} # configure this in your shell when testing

node permissions-migration.js