'use strict'
var http = require('http')
var https = require('https')
var url = require('url')
var lib = require('http-helper-functions')
var templates = require('./templates.js')

var edgeHost = process.env.EDGE_HOST
var clientId = process.env.CLIENT_ID
var clientSecret = process.env.CLIENT_SECRET

function migrateRolesFromEdge(req, res, reqObj) {

  if (reqObj.org == null)
    lib.badRequest(req, res, 'json property org required')
  else if (reqObj.baseLocation == null)
    lib.badRequest(req, res, 'json property baseLocation required')
  else {
    getRoleDetailsFromEdge(req, res, reqObj.org, function (edgeRolesAndPermissions) {

      // the org exists, create initial permissions document
      var orgPermission = templates.orgPermission(reqObj.baseLocation, reqObj.org, lib.getUser(req))
      lib.createPermissonsFor(req, res, orgPermission._subject, orgPermission, function (permissionsURL, permissions, responseHeaders) {

        var ifMatch = responseHeaders['etag']

        //console.log('edge roles and permissions ---> '+JSON.stringify(edgeRolesAndPermissions))
        var edgeRoles = Object.keys(edgeRolesAndPermissions)
        var allUsers = []
        for (var i=0; i < edgeRoles.length; i++) {
          allUsers = allUsers.concat(edgeRolesAndPermissions[edgeRoles[i]].users) // allows duplicates, that's fine
        }
        var userAuth = req.headers.authorization
        // build up a new request object with the client credentials used for getting user UUIDs from their emails
        var clientAuthEncoded = new Buffer(clientId + ':' + clientSecret).toString('base64')
        var tokenReq = {}
        tokenReq.headers = {}
        tokenReq.headers['authorization'] = 'Basic ' + clientAuthEncoded
        tokenReq.headers['Accept'] = 'application/json'
        tokenReq.headers['Content-Type'] = 'application/x-www-form-urlencoded'

        // get client credentials token with scim.ids read scope so we can translate emails to user UUIDs
        sendExternalRequest(tokenReq, res, true, 'login.e2e.apigee.net', '/oauth/token', 'POST', 'grant_type=client_credentials', function (clientRes) {

          var body = ''
          clientRes.on('data', function (d) {body += d})
          clientRes.on('end', function () {
            var clientToken = JSON.parse(body).access_token
            var userReq = {}
            userReq.headers = {}
            userReq.headers['Accept'] = 'application/json'
            userReq.headers['Content-Type'] = 'application/json'
            userReq.headers.authorization = 'Bearer ' + clientToken

            // translate the user emails to their SSO UUIDs
            sendExternalRequest(userReq, res, true, 'login.e2e.apigee.net', '/ids/Users/emails/', 'POST', JSON.stringify(allUsers), function (clientRes) {

              var body = ''
              clientRes.on('data', function (d) {body += d})
              clientRes.on('end', function () {
                var emailToPermissionsUserMapping = {}
                var ssoUsers = JSON.parse(body)
                for (var j = 0; j < ssoUsers.length; j++) {
                  emailToPermissionsUserMapping[ssoUsers[j].email] = 'https://login.e2e.apigee.net#' + ssoUsers[j].id
                }

                //console.log('email to users mapping ---> '+JSON.stringify(emailToPermissionsUserMapping))

                var rolesProcessed = 0
                var patchedOrgPermissions = permissions
                for (var i = 0; i < edgeRoles.length; i++) {
                  var permissionsUsers = []
                  for ( var k=0; k < edgeRolesAndPermissions[edgeRoles[i]].users.length; k++){
                    if (emailToPermissionsUserMapping[edgeRolesAndPermissions[edgeRoles[i]].users[k]] !== null)
                      permissionsUsers.push(emailToPermissionsUserMapping[edgeRolesAndPermissions[edgeRoles[i]].users[k]])
                  }

                  // we have all the users' UUIDs for this role, now lets create the team in the permissions service using original request object
                  var headers = {
                    'accept': 'application/json',
                    'content-type': 'application/json',
                    'authorization': userAuth
                  }
                  lib.sendInternalRequest(req, res, '/teams', 'POST', JSON.stringify(templates.team(reqObj.baseLocation, reqObj.org, edgeRoles[i], permissionsUsers)), headers, function (clientRes) {
                    rolesProcessed++
                    var body = ''
                    clientRes.on('data', function (d) {body += d})
                    clientRes.on('end', function () {
                      body = JSON.parse(body)
                      var teamLocation = clientRes.headers['location']
                      if (body.name.indexOf('orgadmin') !== -1) {
                        // add permissions to modify the org's permission document
                        patchedOrgPermissions._permissions.read.push(teamLocation)
                        patchedOrgPermissions._permissions.update.push(teamLocation)
                        patchedOrgPermissions._permissions.delete.push(teamLocation)


                        // add permissions for the org resource
                        patchedOrgPermissions._self.read.push(teamLocation)
                        patchedOrgPermissions._self.update.push(teamLocation)
                        patchedOrgPermissions._self.delete.push(teamLocation)

                        // add permissions heirs
                        patchedOrgPermissions._permissionsHeirs.read.push(teamLocation)
                        patchedOrgPermissions._permissionsHeirs.add.push(teamLocation)
                        patchedOrgPermissions._permissionsHeirs.remove.push(teamLocation)

                        // add shipyard permissions
                        patchedOrgPermissions.shipyardEnvironments.create = []
                        patchedOrgPermissions.shipyardEnvironments.create.push(teamLocation)

                        patchedOrgPermissions.shipyardEnvironments.read = []
                        patchedOrgPermissions.shipyardEnvironments.read.push(teamLocation)

                      }
                      else if (body.name.indexOf('opsadmin') !== -1) {
                        patchedOrgPermissions._self.read.push(teamLocation)
                        patchedOrgPermissions._permissionsHeirs.read.push(teamLocation)
                        patchedOrgPermissions._permissionsHeirs.add.push(teamLocation)

                      }
                      else if (body.name.indexOf('businessuser') !== -1) {
                        patchedOrgPermissions._self.read.push(teamLocation)
                        patchedOrgPermissions._permissionsHeirs.read.push(teamLocation)
                        patchedOrgPermissions._permissionsHeirs.add.push(teamLocation)

                      }
                      else if (body.name.indexOf('user') !== -1) {
                        patchedOrgPermissions._self.read.push(teamLocation)
                        patchedOrgPermissions._permissionsHeirs.read.push(teamLocation)
                        patchedOrgPermissions._permissionsHeirs.add.push(teamLocation)

                      }
                      else if (body.name.indexOf('readonlyadmin') !== -1) {
                        patchedOrgPermissions._permissions.read.push(teamLocation)

                        // add permissions for the org resource
                        patchedOrgPermissions._self.read.push(teamLocation)

                        // add permissions heirs
                        patchedOrgPermissions._permissionsHeirs.read.push(teamLocation)

                      }
                      else {
                        // not a standard Edge role, just add read permissions for the org for now
                        patchedOrgPermissions._self.read.push(teamLocation)
                        patchedOrgPermissions._permissionsHeirs.read.push(teamLocation)
                        patchedOrgPermissions._permissionsHeirs.add.push(teamLocation)

                      }

                      // now patch the permissions for the org after looping through all the roles(teams)
                      if (rolesProcessed === edgeRoles.length) {
                        var headers = {
                          'content-type': 'application/merge-patch+json',
                          'if-match': ifMatch,
                          'authorization': userAuth
                        }
                        lib.sendInternalRequest(req, res, '/permissions?' + patchedOrgPermissions._subject, 'PATCH', JSON.stringify(patchedOrgPermissions), headers, function (clientRes) {
                          var body = ''
                          clientRes.on('data', function (d) {body += d})
                          clientRes.on('end', function () {
                            if (clientRes.statusCode === 200)
                              lib.respond(req, res, clientRes.statusCode, clientRes.headers, patchedOrgPermissions, 'application/json')
                            else
                              lib.internalError(res, 'failed to patch permissions for org, err: ' + body)
                          })
                        })
                      }
                    })
                  })
                }
              })
            })
          })
        })
      })
    })
  }
}

function getRoleDetailsFromEdge(req, res, organization, callback) {
  if (organization == null) {
    lib.badRequest(res, 'organization must be provided')
  }
  sendExternalRequest(req, res, true, edgeHost, '/v1/o/' + organization + '/userroles', 'GET', null, function (response) {
    var edgeRolesAndPermissions = {}
    var body = ''
    response.on('data', function (d) {body += d})
    response.on('end', function () {
      var roles = JSON.parse(body)
      var processed = 0
      roles.forEach(x => {
        //console.log('getting role details for role: '+x)
        edgeRolesAndPermissions[x] = {}
        getRoleUsersFromEdge(req, res, organization, x, function (users) {
          edgeRolesAndPermissions[x]['users'] = users
          getRolePermissionsFromEdge(req, res, organization, x, function (permissions) {
            processed++
            edgeRolesAndPermissions[x]['permissions'] = permissions
            if (processed === roles.length)
              callback(edgeRolesAndPermissions)
          })
        })
      })
    })
  })
}


function getRoleUsersFromEdge(req, res, org, role, callback) {
  sendExternalRequest(req, res, true, edgeHost, '/v1/o/' + org + '/userroles/' + role + '/users', 'GET', null, function (response) {
    var body = ''
    response.on('data', function (d) {body += d})
    response.on('end', function () {
      callback(JSON.parse(body))
    })
  })
}

function getRolePermissionsFromEdge(req, res, org, role, callback) {
  sendExternalRequest(req, res, true, edgeHost, '/v1/o/' + org + '/userroles/' + role + '/permissions', 'GET', null, function (response) {
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
      lib.getServerPostObject(req, res, migrateRolesFromEdge)
    else
      lib.methodNotAllowed(req, res, ['POST'])
  }
  else
    lib.notFound(req, res)
}


function sendExternalRequest(serverReq, res, useHttps, host, path, method, body, callback) {
  var headers = {
    'Accept': 'application/json',
  }
  if (body) {
    headers['Content-Type'] = serverReq.headers['Content-Type'] || 'application/json'
    headers['Content-Length'] = Buffer.byteLength(body)
  }
  if (serverReq.headers.authorization !== undefined)
    headers.authorization = serverReq.headers.authorization

  var hostParts = host.split(':')
  var options = {
    hostname: hostParts[0],
    path: path,
    method: method,
    headers: headers,
    rejectUnauthorized: false // TODO make this configurable. used because apigee doesn't generate certs properly
  }
  if (hostParts.length > 1)
    options.port = hostParts[1]

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
http.createServer(requestHandler).listen(port, function () {
  console.log(`server is listening on ${port}`)
})
