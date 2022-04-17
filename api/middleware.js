const jwt = require('jsonwebtoken');

const verify = (req, res, next) => {
    const tokenHeader = req.headers.token;

    if (tokenHeader) {
        const token = tokenHeader.split(' ').pop();

        jwt.verify(token, process.env.SECRET_KEY, (error, payload) => {
            if (error) {
                return res.status(403).json('Firbidden access: Token is not valid.');
            }

            req.user = payload;
            return next();
        });

    } else {
        return res.status(401).json('Unauthorized.');
    }
}

module.exports = verify;