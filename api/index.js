const express = require('express');
const app = express();
const dotenv = require('dotenv');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { generateAccessToken, generateRefreshToken } = require('./token-helper');
const verify = require('./middleware');
const data = require('./data');

dotenv.config();
app.use(cors());
app.use(express.json());


// For better expirience to store tokens should use any 'DB' or 'Redis' store
let refreshTokens = [];
let users = [...data];

app.post('/api/refresh', (req, res) => {
    //  take token from the user
    const refreshToken = req.body.token;

    // send error if no or invalid token
    if (!refreshToken) {
        return res.status(401).json('Unauthorized.');
    }

    if (!refreshTokens.includes(refreshToken)) {
        return res.status(403).json('Refresh token is invalid.');
    }

    jwt.verify(refreshToken, process.env.REFRESH_SECRET_KEY, (error, payload) => {
        if (error) {
            return console.error(error);
        }

        refreshTokens = refreshTokens.filter(token => token !== refreshToken);

        // if everything okay, create a new one and send to the user
        const newAccessToken = generateAccessToken(payload);
        const newRefreshToken = generateRefreshToken(payload);

        refreshTokens.push(newRefreshToken);
        res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken
        });
    });
})

app.post('/api/login', (req, res) => {
    // console.log(req.body);
    const {name, password} = req.body;

    const user = users.find(user => {
        return user.name === name && user.password === password;
    });

    if (user) {
        // Generate access token
        const accessToken = generateAccessToken(user);
        // Generate refresh token
        const refreshToken = generateRefreshToken(user);

        refreshTokens.push(refreshToken);

        return res.status(200).json({
            name: user.name,
            isAdmin: user.isAdmin,
            accessToken,
            refreshToken
        });
    }
    return res.status(404).json('User not found...');
});

app.post('/api/logout', verify, (req, res) => {
    const refreshToken = req.body.token;

    if (!refreshTokens.includes(refreshToken)) {
        return res.status(403).json('Refresh token is invalid.');
    }

    refreshTokens = refreshTokens.filter(token => token !== refreshToken);

    res.status(200).json('Logged out successfully.');
})


app.delete('/api/user/:id', verify, (req, res) => {
    // console.log('body: ', req.user, req.params.id);

    if (req.user.id === Number(req.params.id) || req.user.isAdmin) {
        // users = users.filter(user => user.id !== Number(req.params.id));
        // console.log(users);
        return res.status(200).json('User has been deleted successfully.');
    }

    return res.status(403).json('You can not delete this user.');
});

app.listen(process.env.PORT, () => {
    console.log(`Backend is running on ${process.env.PORT}...`);
});