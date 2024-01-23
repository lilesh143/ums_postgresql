const { DB_HOST, DB_USERNAME, DB_PASSWORD, DB_NAME } = process.env;


const { Pool } = require('pg');

const pool = new Pool({
    host: DB_HOST,
    port: 5432,
    user: DB_USERNAME,
    password: DB_PASSWORD,
    database: DB_NAME
})

pool.connect(function(err) {
    if (err) throw err;
    console.log(DB_NAME + ' database connected successfully');
})

// console.log("postgresql data base connected successfully")



module.exports = pool;






// var mysql = require('mysql');

// var conn = mysql.createConnection({
//     host: DB_HOST,
//     user: DB_USERNAME,
//     password: DB_PASSWORD,
//     database: DB_NAME
// })

// conn.connect(function(err) {
//     if (err) throw err;
//     console.log(DB_NAME + ' database connected successfully');

// })

// module.exports = conn;