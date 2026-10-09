import express from 'express';
const mysql = require('mysql');
const database = mysql.createConnection({host: 'localhost'});
const app = express();

app.get('/ts/sql', function(req: express.Request, res: express.Response) {
    database.query("SELECT name FROM users WHERE name = '" + req.query.name + "'");
    res.send('done');
});

app.get('/ts/xss', function(req: express.Request, res: express.Response) {
    res.send('<h1>' + req.query.name + '</h1>');
});

app.get('/ts/safe', function(req: express.Request, res: express.Response) {
    database.query('SELECT name FROM users WHERE name = ?', [req.query.name]);
    res.json({name: req.query.name});
});
