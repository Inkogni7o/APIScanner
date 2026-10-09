const express = require('express');
const app = express();

app.get('/js/nosql', function(req, res) {
    collection.find({$where: req.query.filter});
    res.send('done');
});

app.get('/js/safe', function(req, res) {
    collection.find({name: String(req.query.name)});
    res.json({name: req.query.name});
});
