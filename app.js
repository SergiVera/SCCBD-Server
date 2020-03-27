'use strict';

const router = require('./routes');
const express = require('express');
const BodyParser = require('body-parser');
const app = express();
const api = require('./routes');
const cors = require('cors');

//app.use(cors({origin: 'http://localhost:4200'}, {origin: 'http://localhost:3001'}));
app.use(cors({origin: 'http://localhost:4200'}))

app.use('/v1', router);

app.use(BodyParser.urlencoded({ extended: false}));

app.use(BodyParser.json());

app.use('', api);

module.exports = app;
