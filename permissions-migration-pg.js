'use strict'
var Pool = require('pg').Pool

var config = {
  host: process.env.PG_HOST,
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  database: process.env.PG_DATABASE
};

var pool = new Pool(config);

function recordMigration(orgURL, data) {
  var time = Date.now()
  var query = `INSERT INTO migrations (orgURL, migrating, migrationtime, data) values ('${orgURL}', FALSE, ${time}, '${JSON.stringify(data)}') ON CONFLICT (orgURL) DO UPDATE SET data = EXCLUDED.data, migrating = EXCLUDED.migrating, migrationtime = EXCLUDED.migrationtime`
  pool.query(query, function (err, pgResult) {
    if (err) 
      console.log(`unable to write migration record for ${orgURL} err: ${err}`)
    else
      console.log(`wrote migration record for ${orgURL} at time ${time}`)
  });
}

function init(callback) {
  var query = 'CREATE TABLE IF NOT EXISTS migrations (orgURL text primary key, migrating boolean, migrationtime bigint, data jsonb);'  
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
          console.log('permissions-migration-db: connected to PG, config: ', config)
          callback()
        }
      })    
  })
}

exports.init = init
exports.recordMigration = recordMigration
