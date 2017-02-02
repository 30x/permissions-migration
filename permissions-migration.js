'use strict'
const http = require('http')
const https = require('https')
const url = require('url')
const lib = require('http-helper-functions')
const rLib = require('response-helper-functions')
const templates = require('./templates.js')
const pLib = require('permissions-helper-functions')
const db = require('./permissions-migration-pg.js')

const CONFIGURED_EDGE_ADDRESS = process.env.EDGE_ADDRESS // something of the form https://api.e2e.apigee.net or https://api.enterprise.apigee.net
const CONFIGURED_EDGE_HOST = CONFIGURED_EDGE_ADDRESS.split(':')[1].replace('//', '') // // something of the form api.e2e.apigee.net or api.enterprise.apigee.net
const CLIENT_ID = process.env.PERMISSIONS_MIGRATION_CLIENTID
const CLIENT_SECRET = process.env.PERMISSIONS_MIGRATION_CLIENTSECRET

function handleErr(req, res, err, param, callback) {
  if (err == 404) 
    rLib.notFound(res, `//${req.headers.host}${req.url} not found`)
  else if (err == 400)
    rLib.badRequest(res, param)
  else if (err == 409)
    lib.duplicate(res, param)
  else if (err == 500)
    rLib.internalError(res, param)
  else if (err)
    rLib.internalError(res, err)
  else 
    callback()
}

function handleMigrationRequest(req, res, body){
  withClientCredentialsDo(req.headers.authorization, function(err, issuer, clientToken) {
    handleErr(req, res, err, issuer, function() {
      verifyMigrationRequest(body, function(err, orgName, orgURL) {
        handleErr(req, res, err, orgName, function() {
          attemptMigration(clientToken, orgName, orgURL, issuer, clientToken, function(err, param) {
            handleErr(req, res, err, param, function() {
              rLib.ok(res)
            })
          })
        })
      })
    })
  })
}

function handleReMigrationRequest(req, res, body){ 
  withClientCredentialsDo(req.headers.authorization, function(err, issuer, clientToken) { 
    handleErr(req, res, err, issuer, function() {
      verifyMigrationRequest(body, function(err, orgName, orgURL) {
        handleErr(req, res, err, orgName, function() {
          performMigration(orgName, orgURL, issuer, clientToken, function(err, param) {
            if (err == 'busy')
              rLib.badRequest(res, `migration in progress for org: ${orgURL}`)
            else  
              handleErr(req, res, err, orgName, function() {
                rLib.ok(res)              
              })
          })
        })
      })
    })
  })
}

function verifyMigrationRequest(body, callback) {
  if(body.resource == null)
    callback(400, 'json property resource is required')
  else {
    var orgRegex = new RegExp("^(?:http://|https://)(.*)/v1/(?:o|organizations)/(.*)/?.*$")
    var matches = body.resource.match(orgRegex)
    if(!matches || matches.length < 3 || CONFIGURED_EDGE_HOST !== matches[1])
      // doesn't look like an Edge resource or the configured edge hostname does not match the resource's hostname
      callback(404)
    else {
      var resource = matches[0]
      var edgeHost = matches[1]
      var orgName = matches[2]
      var orgURL = CONFIGURED_EDGE_ADDRESS + '/v1/o/' + orgName
      if (orgName == null)
        callback(400, 'orgName required in order to migrate permissions')
      else
        callback(null, orgName, orgURL)
    }
  }
} 

function attemptMigration (auth, orgName, orgURL, issuer, clientToken, callback) {
  var retryCount = 0;
  function seeIfMigrationNeeded () {
    // check to see if permissions already exist first
    lib.sendInternalRequest('GET', `/permissions?${orgURL}`, {authorization: `Bearer ${clientToken}`}, null, function(err, clientRes){
      if (err)
        callback(500, `unable to GET permissions: /permissions?${orgURL} err: ${err}`)
      else if (clientRes.statusCode == 200)
        callback(409, `Permissions already exist for ${orgURL}`)
      else if (clientRes.statusCode == 404)
        performMigration(orgName, orgURL, issuer, clientToken, function(err, param) {
          if (err == 'busy')
            setTimeout(function() {
              if(++retryCount < 2)
                seeIfMigrationNeeded ()
              else
                callback(500, `unable to get migration flag for orgURL ${orgURL}`)
            }, 1000)
          else  
            callback(err, param)
        })
      else
        callback(500, 'status: '+clientRes.statusCode+', unable to verify if permissions already exist for resource '+orgURL)
    })
  }
  seeIfMigrationNeeded ()
}

function performMigration(orgName, orgURL, issuer, clientToken, callback) {
  db.setMigratingFlag(orgName, orgURL, function(err, migrating, migrationRecord) {
    if (err)
      callback(500, `unable to set migrating flag. err: ${err}`)
    else if (migrating) {
      console.log(`migration request while migration request in progress for ${orgURL}`)
      callback('busy')
    } else
      migrateOrgPermissionsFromEdge(orgName, orgURL, issuer, clientToken, migrationRecord, callback)
  })  
}

function withClientCredentialsDo(auth, callback) {
  // build up a new request object with the client credentials used for getting user UUIDs from their emails
  var requestUser = lib.getUser(auth)
  var issuer = requestUser.split('#')[0]  
  var clientAuthEncoded = new Buffer(CLIENT_ID + ':' + CLIENT_SECRET).toString('base64')
  var tokenHeaders = {}
  tokenHeaders['authorization'] = 'Basic ' + clientAuthEncoded
  tokenHeaders['Accept'] = 'application/json'
  tokenHeaders['Content-Type'] = 'application/x-www-form-urlencoded'
  // get client credentials token with scim.ids read scope so we can translate emails to user UUIDs
  sendExternalRequest(tokenHeaders, issuer, '/oauth/token', 'POST', 'grant_type=client_credentials', function (err, clientRes) {
    if (err)
      callback(500, `unable to authenticate with IDs service to perform migration. err: ${err}`)
    else
      lib.getClientResponseBody(clientRes, function (body) {
        if (clientRes.statusCode == 200) {
          var clientToken = JSON.parse(body).access_token
          callback(null, issuer, clientToken)
        } else
          callback(500, `unable to authenticate with IDs service to perform migration. statusCode: ${clientRes.statusCode}`)
      })
  })
}

function withEdgeUserUUIDsDo(issuer, clientToken, edgeRolesAndPermissions, callback) {
  var clientHeaders = {}
  clientHeaders['Accept'] = 'application/json'
  clientHeaders['Content-Type'] = 'application/json'
  clientHeaders.authorization = 'Bearer ' + clientToken

  // translate the user emails to their SSO UUIDs
  var allUsers = []
  for (var edgeRoleName in edgeRolesAndPermissions) {
    allUsers = allUsers.concat(edgeRolesAndPermissions[edgeRoleName].users) // allows duplicates, that's fine
  }
  sendExternalRequest(clientHeaders, issuer, '/ids/Users/emails/', 'POST', JSON.stringify(allUsers), function (err, clientRes) {
    if (err)
      callback(err, clientRes)
    else if (clientRes.statusCode !== 200)
      callback(500, 'unable to obtain UUIDs for Edge users')
    else {
      lib.getClientResponseBody(clientRes, function (body) {
        var ssoUsers = JSON.parse(body)
        callback(null, ssoUsers)
      })
    }
  })
}

function buildTeam(orgName, orgURL, edgeRoleName, edgeRole, emailToPermissionsUserMapping) {
  var permissionsUsers = edgeRole.users.map(user => emailToPermissionsUserMapping[user])
  var team = templates.team(orgName, orgURL, edgeRoleName, permissionsUsers)
  team.roles = {}
  var teamRole = {}
  team.roles[orgURL] = teamRole
  var resourcePermission = edgeRole.permissions.resourcePermission
  for (var i=0; i< resourcePermission.length; i++)
    teamRole[resourcePermission[i].path] = resourcePermission[i].permissions  
  return team
}

function migrateOrgPermissionsFromEdge(orgName, orgURL, issuer, clientToken, migrationRecord, callback) {
  var existingTeams = migrationRecord.teams
  var headers = {
    'accept': 'application/json',
    'content-type': 'application/json',
    'authorization': `Bearer ${clientToken}`
  }
  getRoleDetailsFromEdge(headers, orgName, function (err, edgeRolesAndPermissions) {
    if (err)
      callback(err, edgeRolesAndPermissions)
    else  
      // the org exists, create initial permissions document
      withEdgeUserUUIDsDo(issuer, clientToken, edgeRolesAndPermissions, function(err, ssoUsers) {
        if (err)
          callback(err, ssoUsers)
        else {
          var emailToPermissionsUserMapping = {}
          for (var j = 0; j < ssoUsers.length; j++) {
            emailToPermissionsUserMapping[ssoUsers[j].email] = issuer + '#' + ssoUsers[j].id
          }
          var CLIENT_ID = lib.getUserFromToken(clientToken)
          var orgPermission = templates.orgPermission(orgName, orgURL, CLIENT_ID)
          if (migrationRecord.initialMigration) // permissions-migration-pg.js sets initialMigration
            lib.sendInternalRequest('POST','/permissions', headers, JSON.stringify(orgPermission), function (err, clientRes) { 
              lib.getClientResponseBody(clientRes, function(data) {
                if (err || clientRes.statusCode != 201) {
                  callback(err, `unable to create permissions for org. statuscode: ${err}`)                
                } else
                  makeTeams()
              })
            })
          else
            makeTeams()
        }

        function makeTeams() {
          // main loop creating teams. permissions resource for org is updated when the last team has been created.
          var totalNumberOfRoles = Object.keys(edgeRolesAndPermissions).length
          var rolesProcessed = 0
          var teams = {}
          for (let edgeRoleName in edgeRolesAndPermissions) {
            var team = buildTeam(orgName, orgURL, edgeRoleName, edgeRolesAndPermissions[edgeRoleName], emailToPermissionsUserMapping)
            if (edgeRoleName in existingTeams)
              lib.sendInternalRequest('PUT', existingTeams[edgeRoleName], headers, JSON.stringify(team), function (err, clientRes) { 
                lib.getClientResponseBody(clientRes, function (body) {
                  if (clientRes.statusCode == 404) { // we had a team but its gone
                    lib.sendInternalRequest('POST', '/teams', headers, JSON.stringify(team), function (err, clientRes) {
                      if (err)
                        callback(err, clientRes)
                      else
                        lib.getClientResponseBody(clientRes, function (body) {
                          addRoleToOrg(clientRes, edgeRoleName, body, false)
                        })
                    })
                  } else
                    addRoleToOrg(clientRes, edgeRoleName, body, true)
                })
              })
            else
              lib.sendInternalRequest('POST', '/teams', headers, JSON.stringify(team), function (err, clientRes) {
                if (err)
                  callback(er, clientRes)
                else
                  lib.getClientResponseBody(clientRes, function (body) {
                    addRoleToOrg(clientRes, edgeRoleName, body, false)
                  })
              })
          }

          function addRoleToOrg(clientRes, edgeRoleName, body, replacedWithPut) {
            rolesProcessed++
            if (clientRes.statusCode == 201 || clientRes.statusCode == 200) {
              teams[edgeRoleName] = clientRes.headers.location
              body = JSON.parse(body)
              var teamLocation = clientRes.headers['location']
              updateOrgPermissons(orgPermission, body.name, teamLocation)
            } else
              console.log(`unable to ${replacedWithPut ? 'update' : 'create'} team. orgName: ${orgName} role: ${edgeRoleName} stauts: ${clientRes.statusCode} body ${body}`)

            // now create the permissions for the org after looping through all the roles(teams)
            if (rolesProcessed === totalNumberOfRoles) {
              lib.sendInternalRequest('PUT', `/permissions?${orgURL}`, headers, JSON.stringify(orgPermission), function (err, clientRes) {
                if (err)
                  callback(err, clientRes)
                else 
                db.writeMigrationRecord(orgPermission._subject, {orgName: orgName, teams: teams})   
                lib.getClientResponseBody(clientRes, function(body) {
                  if (clientRes.statusCode == 200)
                    callback(null)
                  else 
                    callback(500, {statusCode: clientRes.statusCode, msg: `failed to create permissions for ${orgURL} statusCode ${clientRes.statusCode} message ${body}`})
                })
              })
            }
          }    
        }
      })
  })
}

function updateOrgPermissons(orgPermission, roleNames, teamLocation) {
  if (roleNames.indexOf('orgadmin') !== -1) {
    // add permissions for the org resource
    orgPermission._self.read.push(teamLocation)

    // add permissions heirs
    orgPermission._permissionsHeirs.read.push(teamLocation)
    orgPermission._permissionsHeirs.add.push(teamLocation)
    orgPermission._permissionsHeirs.remove.push(teamLocation)

    // add shipyard permissions
    orgPermission.shipyardEnvironments.create = []
    orgPermission.shipyardEnvironments.create.push(teamLocation)

    orgPermission.shipyardEnvironments.read = []
    orgPermission.shipyardEnvironments.read.push(teamLocation)

  } else if (roleNames.indexOf('opsadmin') !== -1) {
    orgPermission._self.read.push(teamLocation)
    orgPermission._permissionsHeirs.read.push(teamLocation)
    orgPermission._permissionsHeirs.add.push(teamLocation)

  } else if (roleNames.indexOf('businessuser') !== -1) {
    orgPermission._self.read.push(teamLocation)
    orgPermission._permissionsHeirs.read.push(teamLocation)
    orgPermission._permissionsHeirs.add.push(teamLocation)

  } else if (roleNames.indexOf('user') !== -1) {
    orgPermission._self.read.push(teamLocation)
    orgPermission._permissionsHeirs.read.push(teamLocation)
    orgPermission._permissionsHeirs.add.push(teamLocation)

  } else if (roleNames.indexOf('readonlyadmin') !== -1) {
    orgPermission._permissions.read.push(teamLocation)

    // add permissions for the org resource
    orgPermission._self.read.push(teamLocation)

    // add permissions heirs
    orgPermission._permissionsHeirs.read.push(teamLocation)

  } else {
    // not a standard Edge role, just add read permissions for the org for now
    orgPermission._self.read.push(teamLocation)
    orgPermission._permissionsHeirs.read.push(teamLocation)
    orgPermission._permissionsHeirs.add.push(teamLocation)
  }
}

function getRoleDetailsFromEdge(callHeaders, orgName, callback) {
  if (orgName == null) 
    callback(400, 'orgName must be provided')
  else {
    var rolesPath = '/v1/o/' + orgName + '/userroles'
    sendExternalRequest(callHeaders, CONFIGURED_EDGE_ADDRESS, '/v1/o/' + orgName + '/userroles', 'GET', null, function (err, response) {
      if (err)
        callback(err, response)
      else
        lib.getClientResponseBody(response, function(body) {
          if (response.statusCode !== 200 )
            callback(500, `Unable to fetch roles from Edge. url: ${rolesPath} status: ${response.statusCode} user: ${lib.getUser(callHeaders.authorization)} body: ${body}`)
          else {
            var edgeRolesAndPermissions = {}
            var roles = JSON.parse(body)
            var processed = 0
            roles.forEach(x => {
              edgeRolesAndPermissions[x] = {}
              getRoleUsersFromEdge(callHeaders, orgName, x, function (err, users) {
                if (err)
                  callback(err, users)
                else {
                  edgeRolesAndPermissions[x]['users'] = users
                  getRolePermissionsFromEdge(callHeaders, orgName, x, function (err, permissions) {
                    if (err)
                      callback(err, permissions)
                    else {
                      processed++
                      edgeRolesAndPermissions[x]['permissions'] = permissions
                      if (processed === roles.length)
                        callback(null, edgeRolesAndPermissions)
                    }
                  })
                }
              })
            })
          }
        })
    })
  }
}

function getRoleUsersFromEdge(callHeaders, orgName, role, callback) {
  sendExternalRequest(callHeaders, CONFIGURED_EDGE_ADDRESS, '/v1/o/' + orgName + '/userroles/' + role + '/users', 'GET', null, function (err, response) {
    if (err)
      callback(err, response)
    else
      lib.getClientResponseBody(response, function (body) {
        callback(null, JSON.parse(body))
      })
  })
}

function getRolePermissionsFromEdge(callHeaders, orgName, role, callback) {
  sendExternalRequest(callHeaders, CONFIGURED_EDGE_ADDRESS, '/v1/o/' + orgName + '/userroles/' + role + '/permissions', 'GET', null, function (err, response) {
    if (err)
      callback(err, response)
    else
      lib.getClientResponseBody(response, function (body) {
        callback(null, JSON.parse(body))
      })
  })
}

function sendExternalRequest(flowThroughHeaders, address, path, method, body, callback) {
  var addressParts = address.toString().split(':')
  var scheme = addressParts[0]
  var host = addressParts[1].replace('//','')
  var useHttps = scheme === 'https'
  var headers = {
    'Accept': 'application/json',
  }
  if (body) {
    headers['Content-Type'] = flowThroughHeaders['Content-Type'] || 'application/json'
    headers['Content-Length'] = Buffer.byteLength(body)
  }
  if (flowThroughHeaders.authorization !== undefined)
    headers.authorization = flowThroughHeaders.authorization
  var options = {
    hostname: host,
    path: path,
    method: method,
    headers: headers,
    rejectUnauthorized: false // TODO make this configurable. used because apigee doesn't generate certs properly
  }
  if (addressParts.length > 2)
    options.port = addressParts[2]

  var clientReq
  if (useHttps)
    clientReq = https.request(options, (clientRes) => callback(null, clientRes))
  else
    clientReq = http.request(options, (clientRes) => callback(null, clientRes))

  clientReq.on('error', function (err) {
    console.log(`sendHttpRequest: error ${err}`)
    callback(500, err)
  })
  if (body) clientReq.write(body)
  clientReq.end()
}

function requestHandler(req, res) {
  if (req.url.startsWith('/permissions-migration/migration-request')) 
    if (req.method == 'POST')
      lib.getServerPostObject(req, res, (x) => handleMigrationRequest(req, res, x))
    else
      rLib.methodNotAllowed(res, ['POST'])
  else if (req.url.startsWith('/permissions-migration/re-migration-request'))
    if (req.method == 'POST')
      lib.getServerPostObject(req, res, (x) => handleReMigrationRequest(req, res, x))
    else
      rLib.methodNotAllowed(res, ['POST'])
  else
    rLib.notFound(res, `//${req.headers.host}${req.url} not found`)
}

function ifAuditShowsChange(orgName, lastMigrationTime, callback) {
  var auditURL = `/v1/audits/organizations/${orgName}/userroles?expand=true&endTime=${lastMigrationTime}`
  callback()
}

function remigrateOnSchedule() {
  var now = Date.now()
  db.getMigrationsOlderThan(now - 30000, function(migrations) {
    for (let i=0; i<migrations.length; i++) {
      var migration = migrations[i]
      var orgURL = migration.orgURL
      var orgName = migration.data.orgName
      var lastMigrationTime = migration.startTime
      ifAuditShowsChange(orgName, lastMigrationTime, function() {})
    }
  })
}

var port = process.env.PORT
function start() {
  db.init(function () {
    http.createServer(requestHandler).listen(port, function () {
      console.log(`server is listening on ${port}`)
    })
  })
}

if (process.env.INTERNAL_SY_ROUTER_HOST == 'kubernetes_host_ip') 
  lib.getHostIPThen(function(err, hostIP){
    if (err) 
      process.exit(1)
    else {
      process.env.INTERNAL_SY_ROUTER_HOST = hostIP
      start()
    }
  })
else 
  start()
