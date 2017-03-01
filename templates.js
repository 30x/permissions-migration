exports.orgPermission = function(org, orgURL, user){
  return {
    _subject: orgURL,
    _self: {
      read: [user],
      update: [user],
      put: [user],
      delete: [user],
      admin: [user],
      govern: [user]
    },
    _permissionsHeirs:{
      add: [user],
      read: [user],
      remove: [user]
    },
    analytics: {},
    apis: {},
    apiproducts: {},
    apps: {},
    audits: {},
    companies: {},
    dailysummaryreport: {},
    developers: {},
    environments: {},
    events: {},
    keyvaluemaps: {},
    keystores: {},
    shipyardEnvironments: {},
    oauth1: {},
    oauth2: {},
    stats: {},
    targetservers: {},
    reports: {},
    resourcefiles: {},
    userroles: {},
    vaults: {},
    virtualhosts: {}
  }
}

exports.envPermission = function(baseLocation, org) {
  return {
    _subject: baseLocation + 'v1/o/' + org + '/environments',
    _inheritsPermissionsFrom: '/o/' + org,
    _self: {
      read: [],
      update: [],
      delete: [],
      admin: [],
      govern: []
    },
    _permissionsHeirs: {
      add: [],
      read: [],
      remove: []
    },
    apis: {},
    resourcefiles: {},
    keystores: {},
    keyvaluemaps: {},
    analytics: {},
    vaults: {},
    caches: {},
    virtualhosts: {},
    targetservers: {}
  }
}

exports.shipyardEnvPermission = function(baseLocation, org) {
  return {
    _subject: baseLocation + 'v1/o/' + org + '/shipyardEnvironments',
    _inheritsPermissionsFrom: '/o/' + org,
    _self: {
      read: [],
      update: [],
      delete: [],
      admin: [],
      govern: []
    },
    _permissionsHeirs: {
      add: [],
      read: [],
      remove: []
    },
    apis: {},
    resourcefiles: {},
    keystores: {},
    keyvaluemaps: {},
    analytics: {},
    vaults: {},
    caches: {},
    virtualhosts: {},
    targetservers: {}
  }
}

//TODO finish this
exports.stdPermission = function(subject, inherits){
  return {
    _resource: {
      _self: "/o/usergrid-e2e/environments/test",
      inheritsPermissionsFrom: "/o/usergrid-e2e/environments"
    },
    _permissions: {
      _self: "/permissions?/o/usergrid-e2e/environments/test"
    }
  }
}

exports.team = function(orgName, orgURL, teamName, members) {
  return {
    isA: 'Team',
    name: orgName + ' '+teamName,
    _permissions: {_inheritsPermissionsOf: [orgURL]},
    members: members,
  }
}
