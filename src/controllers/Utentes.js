const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const speakeasy = require('speakeasy');

module.exports = {
    async getBasicInfo(req, res){
        const utenteID = req.utenteID;
        const utente = await prisma.utentes.findUnique({
            where: {
                userID: utenteID
            }
        });
        res.status(200).json({
            "proc": utente.userProc,
            "nome": utente.nomeCompleto,
            "amigavel": utente.nomeAbreviado,
            "sexo": utente.sexo
        });
    },
    async getSecurityInfo(req, res){
        const utenteID = req.utenteID;
        const utente = await prisma.utentes.findUnique({
            where: {
                userID: utenteID
            }
        });
        if(utente.otp === null){
            res.status(200).json({
                "otpEnable": false
            });
        }else{
            res.status(200).json({
                "otpEnable": true
            }); 
        }
    },
    async getOtpQrCode(req, res){
        const secret = speakeasy.generateSecret();
        const utenteID = req.utenteID;
        const utente = await prisma.utentes.findUnique({
            where: {
                userID: utenteID
            }
        });
        const lastTempOTP = await prisma.OTPTemp.findUnique({
            where: {
                utenteID
            }
        });
        if(lastTempOTP){
            await prisma.OTPTemp.delete({
                where: {
                    utenteID
                }
            });
        }
        await prisma.OTPTemp.create({
            data: {
                utenteID,
                otp: secret.base32
            }
        });
        const otpName = "MyAETTR (" + utente.userProc + ")";
        const qrcodeUrl = "otpauth://totp/" + otpName + "?secret=" + secret.base32;
        res.status(200).json({
            "status": "ok",
            "otp": qrcodeUrl,
            "code": secret.base32
        });
    },
    async activateOTP(req, res){
        const codigo = req.body.otp;
        const user = req.utenteID;
        const tempOpt = await prisma.OTPTemp.findUnique({
            where: {
                utenteID: user
            }
        });
        if(tempOpt){
            const otpVerCode = tempOpt.otp;
            const verifica = speakeasy.totp.verify({ secret: otpVerCode, encoding: 'base32', token: codigo });
            if(verifica){
                await prisma.OTPTemp.delete({
                    where: {
                        utenteID: user
                    }
                });
                await prisma.utentes.update({
                    data: {
                        otp: otpVerCode
                    },
                    where: {
                        userID: user
                    }
                });
                res.status(200).json({
                    "status": "ok"
                });  
            }else{
                res.status(200).json({
                    "status": "error-notvalid",
                    "error": "OTP Invalid"
                });   
            }
        }else{
            res.status(200).json({
                "status": "error",
                "error": "OTP Error"
            });
        }
    },
    async desactivateOTP(req, res){
        const codigo = req.body.otp;
        const user = req.utenteID;
        const utente = await prisma.utentes.findUnique({
            where: {
                userID: user
            }
        });
        if(utente){
            const otpVerCode = utente.otp;
            const verifica = speakeasy.totp.verify({ secret: otpVerCode, encoding: 'base32', token: codigo });
            if(verifica){
                await prisma.utentes.update({
                    data: {
                        otp: null
                    },
                    where: {
                        userID: user
                    }
                });
                res.status(200).json({
                    "status": "ok"
                });  
            }else{
                res.status(200).json({
                    "status": "error-notvalid",
                    "error": "OTP Invalid"
                });   
            }
        }else{
            res.status(200).json({
                "status": "error",
                "error": "OTP Error"
            });
        }
    }
};