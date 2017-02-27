'use strict'
var Pool = require('pg').Pool

var config = {
  host: process.env.PG_HOST,
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  database: process.env.PG_DATABASE
}

var pool = new Pool(config)

const COMPONENT_NAME = 'permissions-migration-pg'
function log(functionName, text) {
  console.log(Date.now(), COMPONENT_NAME, functionName, text)
}

function writeMigrationRecord(orgURL, data) {
  var time = Date.now()
  var query = `UPDATE migrations SET (endtime, data) = (${time}, '${JSON.stringify(data)}')`
  pool.query(query, function (err, pgResult) {
    if (err) 
      log('writeMigrationRecord', `unable to write migration record for ${orgURL} err: ${err}`)
    else
      log('writeMigrationRecord', `wrote migration record for ${orgURL} at time ${time}`)
  })
}

function readMigrationRecord(orgURL, callback) {
  var time = Date.now()
  var query = `SELECT * from migrations WHERE orgURL = '${orgURL}'`
  pool.query(query, function (err, pgResult) {
    if (err) 
      callback(err)
    else
      if (pgResult.rowCount == 0)
        callback(404)
      else
        callback(pgResult.rows[0])
  })
}

function getMigrationsOlderThan(time, callback) {
  var query = `SELECT * from migrations WHERE startTime < ${time}`
  pool.query(query, function (err, pgResult) {
    if (err) 
      callback(err)
    else
      callback(null, pgResult.rows)
  })
}

function setMigratingFlag(orgName, orgURL, callback) {
  var time = Date.now()
  var newRecord = {orgName: orgName, teams:{}, initialMigration: true}
  var query = `INSERT INTO migrations (orgURL, startTime, endTime, data) values ('${orgURL}', ${time}, 0, '${JSON.stringify(newRecord)}') ON CONFLICT (orgURL) DO UPDATE SET startTime = EXCLUDED.startTime WHERE migrations.endTime > migrations.startTime OR (migrations.startTime > migrations.endTime AND migrations.startTime <  ${time - 30000}) RETURNING data`
  pool.query(query, function (err, pgResult) {
    if (err) {
      log('setMigratingFlag', `unable to write migration flag for ${orgURL} err: ${err}`)
      callback(err)
    } else {
      log('setMigratingFlag', `wrote migration flag for ${orgURL} at time ${time}`)
      if (pgResult.rowCount == 0)
        callback(null, true)
      else
        callback(null, false, pgResult.rows[0].data)
    }
  })
}

function init(callback) {
  var query = 'CREATE TABLE IF NOT EXISTS migrations (orgURL text primary key, startTime bigint, endTime bigint, data jsonb)'  
  pool.connect(function(err, client, release) {
    if(err)
      console.error('error creating migrations table', err)
    else
      client.query(query, function(err, pgResult) {
        if(err) {
          release()
          console.error('error creating migrations table', err)
        } else {
          release()
          log('init', `connected to PG, host: ${config.host} database: ${config.database}`)
          callback()
        }
      })    
  })
}

exports.init = init
exports.writeMigrationRecord = writeMigrationRecord
exports.readMigrationRecord = readMigrationRecord
exports.setMigratingFlag = setMigratingFlag
exports.getMigrationsOlderThan = getMigrationsOlderThan