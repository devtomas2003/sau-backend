module.exports = {
    async getTranslation(req, res){
        if(req.params.page == "login" && req.params.lang == "pt"){
            res.status(200).json({
                "serviceAccessing": "Está a aceder ao serviço:",
                "signinText": "Iniciar Sessão",
                "plHolUser": "Utilizador",
                "plHolPass": "Password",
                "errorCredentials": "As credenciais informadas são inválidas!",
                "helpLink": "Não consegue aceder a sua conta?",
                "backBtn": "Voltar",
                "nextBtn": "Proximo",
                "langLink": "en",
                "errorTitle": "Erro na autenticação - Pedido Expirado",
                "errorText": 'Pode estar a ver esta mensagem por ter usado o botão "voltar" ou esperado muito tempo desde que o pedido de autenticação foi feito. Pode também inadvertidamente ter guardado o formulário de autenticação nos "favoritos" ou usado uma ligação inválida.'
            });
        }else if(req.params.page == "login" && req.params.lang == "en"){
            res.status(200).json({
                "serviceAccessing": "You are accessing the service:",
                "signinText": "Sign in",
                "plHolUser": "Username",
                "plHolPass": "Password",
                "errorCredentials": "The credentials provided are invalid!",
                "helpLink": "Can't access your account?",
                "backBtn": "Back",
                "nextBtn": "Next",
                "langLink": "pt",
                "errorTitle": "Authentication Error - Request Expired",
                "errorText": 'You may be seeing this message because you used the "back" button or waited too long since the authentication request was made. You may also have inadvertently saved the login form to "favorites" or used an invalid link.'
            });
        }
    }
};