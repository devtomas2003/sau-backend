const express = require('express');
const ExternalAuth = require('./controllers/externalAuth');
const routes = express.Router();

const Langs = require('./controllers/Langs');
const Utentes = require('./controllers/Utentes');
const Auth = require('./middlewares/Auth');

routes.get('/getLang/:lang', Langs.getTranslation);
routes.post('/getRedirectToken', ExternalAuth.getTokenRedirect);
routes.post('/getRedirectData', ExternalAuth.getRedirectData);
routes.post('/authenticate/:authToken', ExternalAuth.authenticate);
routes.post('/validateOTP/:authToken', ExternalAuth.validateOTP);
routes.get('/password/:pass', ExternalAuth.generatePassword);
routes.get('/undoAuth/:authToken', ExternalAuth.undoAuth);
routes.use(Auth);
routes.get('/validateJwt', ExternalAuth.validateJwt);
routes.get('/basicInfo', Utentes.getBasicInfo);
routes.get('/getSecurityInfo', Utentes.getSecurityInfo);
routes.get('/getOtpQrCode', Utentes.getOtpQrCode);
routes.post('/activateOTP', Utentes.activateOTP);
routes.post('/desactivateOTP', Utentes.desactivateOTP);
routes.get('/logout', ExternalAuth.logout);

module.exports = routes;