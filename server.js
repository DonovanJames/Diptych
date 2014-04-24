var express = require('express')
, 	fs = require('fs')
,	config = require('./config/config.js')
;

var modelsPath = __dirname + '/app/models';
fs.readdirSync(modelsPath).forEach(function (file) {
  if (file.indexOf('.js') >= 0) {
    require(modelsPath + '/' + file);
  }
});

var app = express();
app.use(express.cookieParser());

require('./config/express')(app, config);
require('./config/routes')(app);


console.log("Diptych running on port: "+config.port); 
app.listen(config.port);
