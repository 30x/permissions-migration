'use strict'
const http = require('http')
const https = require('https')
const url = require('url')
const lib = require('http-helper-functions')
const templates = require('./templates.js')
const pLib = require('permissions-helper-functions')
const db = require('./permissions-migration-pg.js')

const CONFIGURED_EDGE_ADDRESS = process.env.EDGE_ADDRESS // something of the form https://api.e2e.apigee.net or https://api.enterprise.apigee.net
const CONFIGURED_EDGE_HOST = CONFIGURED_EDGE_ADDRESS.split(':')[1].replace('//', '') // // something of the form api.e2e.apigee.net or api.enterprise.apigee.net
const CLIENT_ID = process.env.PERMISSIONS_MIGRATION_CLIENTID
const CLIENT_SECRET = process.env.PERMISSIONS_MIGRATION_CLIENTSECRET

function resourceHandler(req, res, reqObj){
  if(reqObj.resource == null)
    lib.badRequest(res, 'json property resource is required')
  else {
    var orgRegex = new RegExp("^(?:http://|https://)(.*)/v1/(?:o|organizations)/(.*)/?.*$")
    var matches = reqObj.resource.match(orgRegex)
    if(!matches || matches.length < 3 || CONFIGURED_EDGE_HOST !== matches[1])
      // doesn't look like an Edge resource or the configured edge hostname does not match the resource's hostname
      lib.notFound(req, res)
    else {
      var resource = matches[0]
      var edgeHost = matches[1]
      var orgName = matches[2]
      var orgURL = CONFIGURED_EDGE_ADDRESS + '/v1/o/' + orgName
      seeIfMigrationNeeded()
    }
  }
  var retryCount = 0;
  function seeIfMigrationNeeded () {
    // check to see if permissions already exist first
    lib.sendInternalRequestThen(req, res, '/permissions?'+reqObj.resource, 'GET', null, {}, function(clientRes){
      if(clientRes.statusCode == 200)
        lib.respond(req,res, 409, {}, {statusCode:409, msg: 'Permissions already exist for '+reqObj.resource})
      else if( clientRes.statusCode == 404)
        if (orgName == null)
          lib.badRequest(req, res, 'orgName required in order to migrate permissions')
        else
          db.setMigratingFlag(orgURL, function(err, migrating, migrationRecord) {
            if (err)
              lib.internalError(res, `unable to set migrating flag. err: ${err}`)
            else
              if (migrating) {
                console.log(`migration request while migration request in progress for ${orgURL}`)
                setTimeout(function() {
                  if(++retryCount < 2)
                    seeIfMigrationNeeded ()
                  else
                    lib.internalError(res, `unable to get migration flag for orgURL ${orgURL}`)
                }, 1000)
              } else
                migrateOrgPermissionsFromEdge(req, res, orgName, orgURL, migrationRecord)
          })
      else
        lib.internalError(res, 'status: '+clientRes.statusCode+', unable to verify if permissions already exist for resource '+reqObj.resource)
    })
  }
}

function withClientCredentialsDo(res, issuer, callback) {
  // build up a new request object with the client credentials used for getting user UUIDs from their emails
  var clientAuthEncoded = new Buffer(CLIENT_ID + ':' + CLIENT_SECRET).toString('base64')
  var tokenReq = {}
  tokenReq.headers = {}
  tokenReq.headers['authorization'] = 'Basic ' + clientAuthEncoded
  tokenReq.headers['Accept'] = 'application/json'
  tokenReq.headers['Content-Type'] = 'application/x-www-form-urlencoded'
  // get client credentials token with scim.ids read scope so we can translate emails to user UUIDs
  sendExternalRequest(tokenReq, res, issuer, '/oauth/token', 'POST', 'grant_type=client_credentials', function (clientRes) {
    if (clientRes.statusCode !== 200)
      lib.internalError(res, 'unable to authenticate with IDs service to perform migration')
    else {
      var body = ''
      clientRes.on('data', function (d) {body += d})
      clientRes.on('end', function () {
        var clientToken = JSON.parse(body).access_token
        callback(clientToken)  
      })
    }
  })
}

function withEdgeUserUUIDsDo(res, issuer, clientToken, edgeRolesAndPermissions, callback) {
  var userReq = {}
  userReq.headers = {}
  userReq.headers['Accept'] = 'application/json'
  userReq.headers['Content-Type'] = 'application/json'
  userReq.headers.authorization = 'Bearer ' + clientToken

  // translate the user emails to their SSO UUIDs
  var allUsers = []
  for (var edgeRoleName in edgeRolesAndPermissions) {
    allUsers = allUsers.concat(edgeRolesAndPermissions[edgeRoleName].users) // allows duplicates, that's fine
  }
  sendExternalRequest(userReq, res, issuer, '/ids/Users/emails/', 'POST', JSON.stringify(allUsers), function (clientRes) {
    if (clientRes.statusCode !== 200)
      lib.internalError(res, 'unable to obtain UUIDs for Edge users')
    else{
      var body = ''
      clientRes.on('data', function (d) {body += d})
      clientRes.on('end', function () {
        var ssoUsers = JSON.parse(body)
        callback(ssoUsers)
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

function migrateOrgPermissionsFromEdge(req, res, orgName, orgURL, migrationRecord) {
  var existingTeams = migrationRecord.teams
  var requestUser = lib.getUser(req.headers.authorization)
  var issuer = requestUser.split('#')[0]
  withClientCredentialsDo(res, issuer, function(clientToken) { 
    var fakeReq = {headers:{authorization: `Bearer ${clientToken}`}}
    getRoleDetailsFromEdge(fakeReq, res, orgName, function (edgeRolesAndPermissions) {
      // the org exists, create initial permissions document
      withEdgeUserUUIDsDo(res, issuer, clientToken, edgeRolesAndPermissions, function(ssoUsers) {
        var emailToPermissionsUserMapping = {}
        for (var j = 0; j < ssoUsers.length; j++) {
          emailToPermissionsUserMapping[ssoUsers[j].email] = issuer + '#' + ssoUsers[j].id
        }
        var CLIENT_ID = lib.getUserFromToken(clientToken)
        var totalNumberOfRoles = Object.keys(edgeRolesAndPermissions).length
        var rolesProcessed = 0
        var orgPermission = templates.orgPermission(orgName, orgURL, CLIENT_ID)

        // main loop creating teams. permissions resource for org is created when the last team has been created.
        var teams = {}
        for (let edgeRoleName in edgeRolesAndPermissions) {
          var headers = {
            'accept': 'application/json',
            'content-type': 'application/json',
            'authorization': `Bearer ${clientToken}`
          }
          var team = buildTeam(orgName, orgURL, edgeRoleName, edgeRolesAndPermissions[edgeRoleName], emailToPermissionsUserMapping)
          if (edgeRoleName in existingTeams)
            lib.sendInternalRequestThen(req, res, existingTeams[edgeRoleName], 'PUT', JSON.stringify(team), headers, (clientRes) => processRole(clientRes, edgeRoleName))
          else
            lib.sendInternalRequestThen(req, res, '/teams', 'POST', JSON.stringify(team), headers, (clientRes) => processRole(clientRes, edgeRoleName))
        }
        function processRole(clientRes, edgeRoleName) {
          rolesProcessed++
          var body = ''
          clientRes.on('data', function (d) {body += d})
          clientRes.on('end', function () {
            if (clientRes.statusCode == 201 || clientRes.statusCode == 200) {
              teams[edgeRoleName] = clientRes.headers.location
              body = JSON.parse(body)
              var teamLocation = clientRes.headers['location']
              if (body.name.indexOf('orgadmin') !== -1) {
                // add permissions to modify the org's permission document
                orgPermission._permissions.read.push(teamLocation)

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

              } else if (body.name.indexOf('opsadmin') !== -1) {
                orgPermission._self.read.push(teamLocation)
                orgPermission._permissionsHeirs.read.push(teamLocation)
                orgPermission._permissionsHeirs.add.push(teamLocation)

              } else if (body.name.indexOf('businessuser') !== -1) {
                orgPermission._self.read.push(teamLocation)
                orgPermission._permissionsHeirs.read.push(teamLocation)
                orgPermission._permissionsHeirs.add.push(teamLocation)

              } else if (body.name.indexOf('user') !== -1) {
                orgPermission._self.read.push(teamLocation)
                orgPermission._permissionsHeirs.read.push(teamLocation)
                orgPermission._permissionsHeirs.add.push(teamLocation)

              } else if (body.name.indexOf('readonlyadmin') !== -1) {
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
            } else
              console.log(`unable to create team. orgName: ${orgName} role: ${edgeRoleName} stauts: ${clientRes.statusCode} body ${body}`)

            // now create the permissions for the org after looping through all the roles(teams)
            if (rolesProcessed === totalNumberOfRoles) {
              pLib.createPermissionsThen(req, res, orgPermission._subject, orgPermission, function (err, permissionsURL, permissions, responseHeaders) {
                db.writeMigrationRecord(orgPermission._subject, {teams: teams})          
                lib.found(req, res, permissions, responseHeaders.etag)
              })
            }
          })
        }        
      })
    })
  })
}

function getRoleDetailsFromEdge(req, res, orgName, callback) {
  if (orgName == null) {
    lib.badRequest(res, 'orgName must be provided')
  }
  var rolesPath = '/v1/o/' + orgName + '/userroles'
  sendExternalRequest(req, res, CONFIGURED_EDGE_ADDRESS, '/v1/o/' + orgName + '/userroles', 'GET', null, function (response) {
    var body = ''
    response.on('data', function (d) {body += d})
    response.on('end', function () {
      if(response.statusCode !== 200 )
        lib.internalError(res, `Unable to fetch roles from Edge. url: ${rolesPath} status: ${response.statusCode} user: ${lib.getUser(req.headers.authorization)} body: ${body}`)
      else {
        var edgeRolesAndPermissions = {}
        var roles = JSON.parse(body)
        var processed = 0
        roles.forEach(x => {
          //console.log('getting role details for role: '+x)
          edgeRolesAndPermissions[x] = {}
          getRoleUsersFromEdge(req, res, orgName, x, function (users) {
            edgeRolesAndPermissions[x]['users'] = users
            getRolePermissionsFromEdge(req, res, orgName, x, function (permissions) {
              processed++
              edgeRolesAndPermissions[x]['permissions'] = permissions
              if (processed === roles.length)
                callback(edgeRolesAndPermissions)
            })
          })
        })
      }
    })
  })
}

function getRoleUsersFromEdge(req, res, orgName, role, callback) {
  sendExternalRequest(req, res, CONFIGURED_EDGE_ADDRESS, '/v1/o/' + orgName + '/userroles/' + role + '/users', 'GET', null, function (response) {
    var body = ''
    response.on('data', function (d) {body += d})
    response.on('end', function () {
      callback(JSON.parse(body))
    })
  })
}

function getRolePermissionsFromEdge(req, res, orgName, role, callback) {
  sendExternalRequest(req, res, CONFIGURED_EDGE_ADDRESS, '/v1/o/' + orgName + '/userroles/' + role + '/permissions', 'GET', null, function (response) {
    var body = ''
    response.on('data', function (d) {body += d})
    response.on('end', function () {
      callback(JSON.parse(body))
    })
  })
}


function requestHandler(req, res) {
  if (req.url.startsWith('/permissions-migration/migration-request')) {
    if (req.method == 'POST')
      lib.getServerPostObject(req, res, (x) => resourceHandler(req, res, x))
    else
      lib.methodNotAllowed(req, res, ['POST'])
  }
  else
    lib.notFound(req, res)
}


function sendExternalRequest(serverReq, res, address, path, method, body, callback) {

  var addressParts = address.toString().split(':')
  var scheme = addressParts[0]
  var host = addressParts[1].replace('//','')
  var useHttps = scheme === 'https'
  //console.log('scheme: '+scheme+', host: '+host+', path: '+path+', method: '+method+', body: '+body)
  var headers = {
    'Accept': 'application/json',
  }
  if (body) {
    headers['Content-Type'] = serverReq.headers['Content-Type'] || 'application/json'
    headers['Content-Length'] = Buffer.byteLength(body)
  }
  if (serverReq.headers.authorization !== undefined)
    headers.authorization = serverReq.headers.authorization

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
    clientReq = https.request(options, callback)
  else
    clientReq = http.request(options, callback)

  clientReq.on('error', function (err) {
    console.log(`sendHttpRequest: error ${err}`)
    lib.internalError(res, err)
  })

  if (body) clientReq.write(body)
  clientReq.end()
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
