'use strict';

const app = require('./app');
const config = require('./config');
const rsa = require('rsa');

//=> = callback function ()
app.listen(config.port, () => {
  console.log(`API REST corriendo en http://localhost:${config.port}`)
});
