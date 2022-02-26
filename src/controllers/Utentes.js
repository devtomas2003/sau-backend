const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

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
    }
};