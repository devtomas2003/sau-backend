const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { v4: uuidv4 } = require('uuid');
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const axios = require('axios');
const speakeasy = require('speakeasy');

module.exports = {
    async getTokenRedirect(req, res){
        const redirectUrl = req.body.redirectUrl;
        if(redirectUrl === undefined){
            return res.status(200).json({
                "status": "error",
                "error": "Missing Redirect Url"
            });
        }else{
            const applicationToken = req.body.appToken;
            const appData = await prisma.applications.findUnique({
                where: {
                    applicationID: applicationToken
                },
                include: {       
                    allowedDomains: true
                }
            });
            if(!appData){
                return res.status(200).json({
                    "status": "error",
                    "error": "Invalid Application Token"
                });
            }else{
                const domains = appData.allowedDomains;
                const httpsplit = redirectUrl.split("/");
                const ports = httpsplit[2].split(":");
                const redirectDomain = ports[0];
                const foundedDomain = domains.find( domain => domain.domain === redirectDomain );
                if(foundedDomain === undefined){
                    return res.status(200).json({
                        "status": "error",
                        "error": "Unauthorized redirect domain"
                    });
                }else{
                    const redirectToken = uuidv4();
                    await prisma.authorization.create({
                        data: {                
                            authorizationID: redirectToken,
                            applicationID: applicationToken,
                            navigatorFingerprint: req.body.navigatorFinger,
                            redirectUrl,
                            redirectTime: new Date(),
                        }
                    });
                    return res.status(200).json({
                        "status": "ok",
                        redirectToken
                    });
                }
            }
        }
    },
    async getRedirectData(req, res){
        const redirectToken = req.body.redirectToken;
        const navigatorToken = req.body.navigatorToken;
        if(redirectToken === undefined){
            res.status(200).json({
                "status": "error",
                "error": "Invalid redirect token"
            });
        }else{
            const authorizationData = await prisma.authorization.findUnique({
                where: {
                    authorizationID: redirectToken
                },
                include: {
                    Applications: true
                }
            });
            if(!authorizationData){
                res.status(200).json({
                    "status": "error",
                    "error": "Invalid redirect token"
                });
            }else{
                if(authorizationData.state === 2 || authorizationData.state === 3){
                    res.status(200).json({
                        "status": "error",
                        "error": "Token already authenticated"
                    });
                }else{
                    if(navigatorToken === authorizationData.navigatorFingerprint){
                        const now = new Date();
                        const redirectMoment = new Date(authorizationData.redirectTime);
                        const difference = (now - redirectMoment) / 1000;
                        if(difference > 60){
                            await prisma.authorization.delete({
                                where: {
                                    authorizationID: redirectToken
                                }
                            });
                            res.status(200).json({
                                "status": "error",
                                "error": "Expired redirect token"
                            });
                        }else{
                            res.status(200).json({
                                "status": "ok",
                                "appName": authorizationData.Applications.applicationName,
                                "backurl": authorizationData.redirectUrl
                            });
                        }
                    }else{
                        await prisma.authorization.delete({
                            where: {
                                authorizationID: redirectToken
                            }
                        });
                        res.status(200).json({
                            "status": "error",
                            "error": "Finger print invalid"
                        });
                    }
                }
            }
        }
    },
    async authenticate(req, res){
        const username = req.body.mail;
        const password = req.body.pass;
        const authToken = req.params.authToken;
        if(!authToken){
            res.status(200).json({
                "status": "error-token",
                "error": "Redirect Token Error"
            });
        }else{
            const utenteData = await prisma.utentes.findFirst({
                where: {
                    email: username
                }
            });
            if(!utenteData){
                res.status(200).json({
                    "status": "error-user",
                    "error": "User not found"
                });
            }else{
                bcrypt.compare(password, utenteData.password, async function(err, result) {
                    if(result){
                        const applicationData = await prisma.authorization.findUnique({
                            where: {
                                authorizationID: authToken
                            },
                            include: {
                                Applications: true
                            }
                        });
                        if(!applicationData){
                            res.status(200).json({
                                "status": "error-token",
                                "error": "Redirect Token Error"
                            });
                        }else{
                            if(applicationData.state === 2 || authorizationData.state === 3){
                                res.status(200).json({
                                    "status": "error-token",
                                    "error": "Token already authenticated"
                                });
                            }else{
                                const now = new Date();
                                const redirectMoment = new Date(applicationData.redirectTime);
                                const difference = (now - redirectMoment) / 1000;
                                if(difference > 60){
                                    await prisma.authorization.delete({
                                        where: {
                                            authorizationID: authToken
                                        }
                                    });
                                    res.status(200).json({
                                        "status": "error-token",
                                        "error": "Redirect Token Error"
                                    });
                                }else{
                                    if(utenteData.otp){
                                        await prisma.authorization.update({
                                            data: {
                                                utenteID: utenteData.userID,
                                                state: 1
                                            },
                                            where: {
                                                authorizationID: authToken
                                            }
                                        });
                                        res.status(200).json({
                                            "status": "ok",
                                            "haveOTP": true
                                        });
                                    }else{
                                        const token = jwt.sign({ id: utenteData.userID, authSession: authToken }, "SAUPlatAETTR", {
                                            expiresIn: 3600*applicationData.Applications.tokenDuration
                                        });
                                        await prisma.authorization.update({
                                            data: {
                                                startTime: new Date(),
                                                endTime: new Date(new Date().setHours(new Date().getHours() + applicationData.Applications.tokenDuration)),
                                                utenteID: utenteData.userID,
                                                state: 2
                                            },
                                            where: {
                                                authorizationID: authToken
                                            }
                                        });
                                        axios.post(applicationData.Applications.callbackUrl, {
                                            sessionToken: authToken,
                                            authToken: token,
                                            fignPrt: applicationData.navigatorFingerprint
                                        }).then(() => {
                                            res.status(200).json({
                                                "status": "ok",
                                            });
                                        }).catch(() => {
                                            res.status(200).json({
                                                "status": "error-internal",
                                            });
                                        });
                                    }
                                }
                            }
                        }
                    }else{
                        res.status(200).json({
                            "status": "error-user",
                            "error": "User not found"
                        });
                    }
                });
            }
        }
    },
    async validateOTP(req, res){
        const otp = req.body.otp;
        const authToken = req.params.authToken;
        if(!authToken){
            res.status(200).json({
                "status": "error-token",
                "error": "Redirect Token Error"
            });
        }else{
        const applicationData = await prisma.authorization.findUnique({
            where: {
                authorizationID: authToken
            },
            include: {
                Applications: true
            }
        });
        if(!applicationData){
            res.status(200).json({
                "status": "error-token",
                "error": "Redirect Token Error"
            });
        }else{
            if(applicationData.state === 2 || authorizationData.state === 3){
                res.status(200).json({
                    "status": "error-token",
                    "error": "Token already authenticated"
                });
            }else{
                const now = new Date();
                const redirectMoment = new Date(applicationData.redirectTime);
                const difference = (now - redirectMoment) / 1000;
                if(difference > 60){
                    await prisma.authorization.delete({
                        where: {
                            authorizationID: authToken
                        }
                    });
                    res.status(200).json({
                        "status": "error-token",
                        "error": "Redirect Token Error"
                    });
                }else{
                    const utente = await prisma.utentes.findUnique({
                        where: {
                            userID: applicationData.utenteID
                        }
                    });
                    const verifica = speakeasy.totp.verify({ secret: utente.otp, encoding: 'base32', token: otp });
                    if(verifica){
                        const token = jwt.sign({ id: utente.userID, authSession: authToken }, "SAUPlatAETTR", {
                            expiresIn: 3600*applicationData.Applications.tokenDuration
                        });
                        await prisma.authorization.update({
                            data: {
                                startTime: new Date(),
                                endTime: new Date(new Date().setHours(new Date().getHours() + applicationData.Applications.tokenDuration)),
                                state: 3
                            },
                            where: {
                                authorizationID: authToken
                            }
                        });
                        axios.post(applicationData.Applications.callbackUrl, {
                            sessionToken: authToken,
                            authToken: token,
                            fignPrt: applicationData.navigatorFingerprint
                        }).then(() => {
                            res.status(200).json({
                                "status": "ok",
                            });
                        }).catch(() => {
                            res.status(200).json({
                                "status": "error-internal",
                            });
                        });
                    }else{
                        res.status(200).json({
                            "status": "error-otp",
                            "error": "Invalid OTP"
                        });
                    }
                }
            }
        }
            }
    },
    async validateJwt(req, res){
        res.status(200).json({ "status": "ok" });
    },
    async undoAuth(req, res){
        const authToken = req.params.authToken;
        await prisma.authorization.delete({
            where: {
                authorizationID: authToken
            }
        });
        res.status(200).json({
            "status": "ok"
        });
    },
    async generatePassword(req, res){
        bcrypt.hash(req.params.pass, 12, function(err, hash) {
            res.send(hash);
        });
    }
};