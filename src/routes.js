const express = require('express');
const ExternalAuth = require('./controllers/externalAuth');
const routes = express.Router();

const Langs = require('./controllers/Langs');

routes.get('/getLang/:page/:lang', Langs.getTranslation);
routes.post('/getRedirectToken', ExternalAuth.getTokenRedirect);
routes.get('/getRedirectData/:redirectToken', ExternalAuth.getRedirectData);
routes.post('/authenticate/:authToken', ExternalAuth.authenticate);
routes.get('/password/:pass', ExternalAuth.generatePassword);

module.exports = routes;