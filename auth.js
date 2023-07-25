const jwt = require('jsonwebtoken');

module.exports = function(req, res, next)
{
    const token = req.cookies.jwt;
    const secret =  'mysecretkey';
    if(!token)
    {
        return res.redirect('/admin');
    }

    try {
        
        const decode = jwt.verify(token, secret);
        req.user = decode.user;
        next();

    } catch (error) {

        return res.redirect('/admin');

    }
}