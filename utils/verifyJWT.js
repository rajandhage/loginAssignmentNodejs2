const jwt = require('jsonwebtoken');

function auth(req, res, next) {
    const token = req.header('auth-token');
    if(!token){
        return res.status(401).send('ACCESS DENIED');
    }
    try{
        const verified = jwt.verify(token, process.env.TOKEN_SECRET);
        req.user = verified;
    }catch(err){
        return res.status(400).send('INVALID TOKEN');
    }

    next();
}

function authEmailVerification(req, res, next) {
    const token = req.query.verificationToken;
    if(!token){
        return res.status(401).send('ACCESS DENIED');
    }
    try{
        const verified = jwt.verify(token, process.env.TOKEN_SECRET);
        req.user = verified;
    }catch(err){
        return res.status(400).send('INVALID TOKEN');
    }

    next();
}

module.exports.auth = auth;
module.exports.authEmailVerification = authEmailVerification;
