const jwt = require("jsonwebtoken");

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
        if(err){
            res.status(200).json({"status": "error", "error": 'token-bad-sign'});
        }else{
            req.utenteID = decoded.id;
            next();
        }
    });
};