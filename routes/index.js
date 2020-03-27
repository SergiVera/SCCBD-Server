'use strict';

const express = require('express');
const communication = require('../controllers/communication');
const api = express.Router();

api.get('/getmsg', communication.getMsg);
api.post('/postmsg', communication.postMsg);
api.post('/sign', communication.signMsg);
api.get('/pubkey', communication.getPublicKey);

module.exports = api;
