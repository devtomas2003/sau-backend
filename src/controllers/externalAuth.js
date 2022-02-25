const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { v4: uuidv4 } = require('uuid');
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

module.exports = {
    async getTokenRedirect(req, res){
        if(req.headers.origin === undefined){
            return res.status(400).json({
                "status": "error",
                "error": "Unknow origin domain"
            });
        }else{
            const httpsplit = req.headers.origin.split("/");
            const ports = httpsplit[2].split(":");
            const domainReq = ports[0];
            const applicationToken = req.params.appToken;
            const appData = await prisma.applications.findUnique({
                where: {
                    applicationID: applicationToken
                },
                include: {       
                    allowedDomains: true
                }
            });
            if(!appData){
                return res.status(400).json({
                    "status": "error",
                    "error": "Invalid Application Token"
                });
            }else{
                const domains = appData.allowedDomains;
                const foundedDomain = domains.find( domain => domain.domain === domainReq );
                if(foundedDomain === undefined){
                    return res.status(401).json({
                        "status": "error",
                        "error": "Unauthorized origin domain"
                    });
                }else{
                    const redirectToken = uuidv4();
                    await prisma.authorization.create({
                        data: {                
                            authorizationID: redirectToken,
                            applicationID: applicationToken,
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
        const redirectToken = req.params.redirectToken;
        if(redirectToken === undefined){
            res.status(400).json({
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
                res.status(400).json({
                    "status": "error",
                    "error": "Invalid redirect token"
                });
            }else{
                if(authorizationData.tokenAuthenticated){
                    res.status(400).json({
                        "status": "error",
                        "error": "Token already authenticated"
                    });
                }else{
                    const now = new Date();
                    const redirectMoment = new Date(authorizationData.redirectTime);
                    const difference = (now - redirectMoment) / 1000;
                    if(difference > 60){
                        await prisma.authorization.delete({
                            where: {
                                authorizationID: redirectToken
                            }
                        });
                        res.status(400).json({
                            "status": "error",
                            "error": "Expired redirect token"
                        });
                    }else{
                        res.status(200).json({
                            "status": "ok",
                            "appName": authorizationData.Applications.applicationName
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
            res.status(400).json({
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
                res.status(401).json({
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
                            res.status(400).json({
                                "status": "error-token",
                                "error": "Redirect Token Error"
                            });
                        }else{
                            if(applicationData.tokenAuthenticated){
                                res.status(400).json({
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
                                    res.status(400).json({
                                        "status": "error-token",
                                        "error": "Redirect Token Error"
                                    });
                                }else{
                                    const token = jwt.sign({ authToken }, "SAUPlatAETTR", {
                                        expiresIn: 3600*applicationData.Applications.tokenDuration
                                    });
                                    await prisma.authorization.update({
                                        data: {
                                            startTime: new Date(),
                                            endTime: new Date(new Date().setHours(new Date().getHours() + applicationData.Applications.tokenDuration)),
                                            tokenAuthenticated: true
                                        },
                                        where: {
                                            authorizationID: authToken
                                        }
                                    });
                                    res.status(200).json({
                                        "status": "ok",
                                        token
                                    });
                                }
                            }
                        }
                    }else{
                        res.status(401).json({
                            "status": "error-user",
                            "error": "User not found"
                        });
                    }
                });
            }
        }
    },
    async generatePassword(req, res){
        bcrypt.hash(req.params.pass, 12, function(err, hash) {
            res.send(hash);
        });
    }
};