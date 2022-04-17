const jwt = require('jsonwebtoken');

const generateAccessToken = (user) => {
    return jwt.sign(
        { id: user.id, isAdmin: user.isAdmin },
        process.env.SECRET_KEY,
        { expiresIn: '10s' }
    );
}

const generateRefreshToken = (user) => {
    return jwt.sign(
        { id: user.id, isAdmin: user.isAdmin },
        process.env.REFRESH_SECRET_KEY
    );
}

module.exports = {
    generateAccessToken,
    generateRefreshToken
}