const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.send('WebApp running');
});

module.exports = app;
