const express = require('express');
const ExternalAuth = require('./controllers/externalAuth');
const routes = express.Router();

const Langs = require('./controllers/Langs');
const Utentes = require('./controllers/Utentes');
const Auth = require('./middlewares/Auth');

routes.get('/getLang/:page/:lang', Langs.getTranslation);
routes.post('/getRedirectToken', ExternalAuth.getTokenRedirect);
routes.get('/getRedirectData/:redirectToken', ExternalAuth.getRedirectData);
routes.post('/authenticate/:authToken', ExternalAuth.authenticate);
routes.get('/password/:pass', ExternalAuth.generatePassword);
routes.get('/undoAuth/:authToken', ExternalAuth.undoAuth);
routes.use(Auth);
routes.get('/validateJwt', ExternalAuth.validateJwt);
routes.get('/basicInfo', Utentes.getBasicInfo);

module.exports = routes;