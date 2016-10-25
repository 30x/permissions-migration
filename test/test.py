import requests
import base64
import json
from os import environ as env
from urlparse import urljoin

EXTERNAL_SCHEME = env['EXTERNAL_SCHEME']
BASE_URL = '%s://%s:%s' % (EXTERNAL_SCHEME, env['EXTERNAL_SY_ROUTER_HOST'], env['EXTERNAL_SY_ROUTER_PORT']) if 'EXTERNAL_SY_ROUTER_PORT' in env else '%s://%s' % (EXTERNAL_SCHEME, env['EXTERNAL_SY_ROUTER_HOST'])

def b64_decode(data):
    missing_padding = (4 - len(data) % 4) % 4
    if missing_padding:
        data += b'='* missing_padding
    return base64.decodestring(data)

if 'APIGEE_TOKEN1' in env:
    TOKEN1 = env['APIGEE_TOKEN1']
else:
    with open('token.txt') as f:
        TOKEN1 = f.read()
USER1 = json.loads(b64_decode(TOKEN1.split('.')[1]))['user_id']

if 'APIGEE_TOKEN2' in env:
    TOKEN2 = env['APIGEE_TOKEN2']
else:
    with open('token2.txt') as f:
        TOKEN2 = f.read()
USER2 = json.loads(b64_decode(TOKEN2.split('.')[1]))['user_id']

if 'APIGEE_TOKEN3' in env:
    TOKEN3 = env['APIGEE_TOKEN3']
else:
    with open('token3.txt') as f:
        TOKEN3 = f.read()
USER3 = json.loads(b64_decode(TOKEN3.split('.')[1]))['user_id']

def main():
    
    print 'sending requests to %s' % BASE_URL

    migration_request = {
        'resource': 'https://api.e2e.apigee.net/v1/o/usergrid-e2e'
    }

    # POST migration-request ( success )
    permissions_migration_url = urljoin(BASE_URL, '/permissions-migration/migration-request')
    headers = {'Content-Type': 'application/json','Authorization': 'Bearer %s' % TOKEN1}
    r = requests.post(permissions_migration_url, headers=headers, json=migration_request)
    if r.status_code == 200:
        print 'correctly migrated edge org %s' % (r.headers['content-location'])
    else:
        print 'failed to migrate edge org for resource %s %s %s' % (migration_request['resource'], r.status_code, r.text)
        return

    # POST migration-request ( conflict )
    permissions_migration_url = urljoin(BASE_URL, '/permissions-migration/migration-request')
    headers = {'Content-Type': 'application/json','Authorization': 'Bearer %s' % TOKEN1}
    r = requests.post(permissions_migration_url, headers=headers, json=migration_request)
    if r.status_code == 409:
        print 'correctly received conflict for resource %s ' % (migration_request['resource'])
    else:
        print 'failed to migrate edge org %s %s' % (r.status_code, r.text)
        return

    # POST migration-request ( bad resource path)
    migration_request = {
        'resource': 'https://api.e2e.apigee.net/v1/notanedgeapi/usergrid-e2e'
    }

    permissions_migration_url = urljoin(BASE_URL, '/permissions-migration/migration-request')
    headers = {'Content-Type': 'application/json','Authorization': 'Bearer %s' % TOKEN1}
    r = requests.post(permissions_migration_url, headers=headers, json=migration_request)
    if r.status_code == 404:
        print 'correctly refused migration for bad resource due to non-edge path %s ' % (migration_request['resource'])
    else:
        print 'failed to refuse migration for bad resource due to non-edge path %s %s' % (r.status_code, r.text)
        return

    # POST migration-request ( bad resource host)
    migration_request = {
        'resource': 'https://api.enterprise.apigee.com/v1/o/usergrid-e2e'
    }

    permissions_migration_url = urljoin(BASE_URL, '/permissions-migration/migration-request')
    headers = {'Content-Type': 'application/json','Authorization': 'Bearer %s' % TOKEN1}
    r = requests.post(permissions_migration_url, headers=headers, json=migration_request)
    if r.status_code == 404:
        print 'correctly refused migration for bad resource due to host mismatch %s ' % (migration_request['resource'])
    else:
        print 'failed to refuse migration for bad resource due to host mismatch %s %s' % (r.status_code, r.text)
        return

    return


if __name__ == '__main__':
    main()