exports.orgPermission = function(baseLocation, org, user){
  return {
    _subject: baseLocation+'/v1/o/'+org,
    _self: {
      read: [user],
      update: [user],
      delete: [user]
    },
    _permissions: {
      read: [user],
      update: [user],
      delete:[user]
    },
    _permissionsHeirs:{
      add: [user],
      read: [user],
      remove: [user]
    },
    environments: {},
    shipyardEnvironments: {},
    keyvaluemaps: {},
    apis: {},
    apps: {},
    apiproducts: {},
    oauth1: {},
    oauth2: {},
    userroles: {},
    resourcefiles: {},
    developers: {},
    companies: {},
    audits: {},
    vaults: {},
    reports: {},
    stats: {},
    dailysummaryreport: {},
    keystores: {},
    analytics: {},
    virtualhosts: {},
    targetservers: {}
  }
}

exports.envPermission = function(baseLocation, org) {
  return {
    _subject: baseLocation + 'v1/o/' + org + '/environments',
    _inheritsPermissionsFrom: '/o/' + org,
    _self: {
      read: [],
      update: [],
      delete: []
    },
    _permissions: {
      read: [],
      update: []
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
      delete: []
    },
    _permissions: {
      read: [],
      update: []
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

exports.team = function(baseLocation, org, teamName, members) {
  return {
    isA: 'Team',
    name: org + ' '+teamName,
    permissions: {_inheritsPermissionsOf: [baseLocation+'/v1/o/'+org]},
    members: members,
  }
}
