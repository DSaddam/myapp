const dbModule = require('../dbModule');
// var mysql = require('mysql'); 
// var conn = mysql.createConnection({
//     host:"sql8.freesqldatabase.com",
//     user:"sql8649549",
//     password:"k9GrEYZ8DR",
//     database: 'sql8649549' 
// }); 
// module.exports = conn;

var mysql = require('mysql');

var pool = mysql.createPool({
    connectionLimit: 10, // Adjust this as needed
    host: "sql8.freesqldatabase.com",
    user: "sql8654366",
    password: "dH3WC7AVW2",
    database: 'sql8654366',
    waitForConnections: true,
    queueLimit: 0
});

pool.on('connection', (connection) => {
    console.log('MySQL Pool connected');
//   dbModule.fetchDataFromDatabase(connection);
});

pool.on('acquire', (connection) => {
    console.log('MySQL Pool connection acquired');
});

pool.on('release', (connection) => {
    console.log('MySQL Pool connection released');
    // dbModule.fetchDataFromDatabase(connection);

});

pool.on('error', (err) => {
    console.error('MySQL Pool error:', err);
    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
        console.log('Attempting to reconnect to MySQL');
        handleDisconnect();
    } else {
        throw err;
    }
});

function handleDisconnect() {
    pool = mysql.createPool({
        connectionLimit: 10,
        host: "sql8.freesqldatabase.com",
        user: "sql8654366",
        password: "dH3WC7AVW2",
        database: 'sql8654366',
        waitForConnections: true,
        queueLimit: 0
    });

    console.log('Reconnected to MySQL');
    dbModule.fetchDataFromDatabase(connection);
}

module.exports = pool;
