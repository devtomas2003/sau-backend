const jwt = require("jsonwebtoken");
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

module.exports = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if(!authHeader){
        res.status(200).json({ "status": "error", "error": "token-unexists" });
    }
    const parts = authHeader.split(' ');
    if(!parts.length === 2){
        res.status(200).json({ "status": "error", "error": "token-error" });
    }
    const [ scheme, token ] = parts;
    if(scheme !== "Bearer"){
        res.status(200).json({ "status": "error", "error": "token-bad-format" });
    }
    jwt.verify(token, "SAUPlatAETTR", async (err, decoded) => {
        const authSession = jwt.decode(token).authSession;
        if(err){
            if(err.name === "TokenExpiredError"){
                await prisma.authorization.update({
                    where: {
                        authorizationID: authSession
                    },
                    data: {
                        state: 4,
                        endTime: new Date()
                    }
                });
                res.status(200).json({"status": "error", "error": 'token-expired'});
            }else{
                res.status(200).json({"status": "error", "error": 'token-bad-sign'});             
            }
        }else{
            const applicationData = await prisma.authorization.findUnique({
                where: {
                    authorizationID: authSession
                }
            });
            if(applicationData){
                if(applicationData.state === 4){
                    res.status(200).json({"status": "error", "error": 'token-expired'});
                }else{
                    req.utenteID = decoded.id;
                    next();
                }
            }else{
                res.status(200).json({"status": "error", "error": 'token-expired'});
            }
        }
    });
};