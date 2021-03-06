const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
require('dotenv').config({ path: 'variables.env' });
const createServer = require('./createServer');
const db = require("./db");

//hi
const server = createServer();

server.express.use(cookieParser());

// Decode the JWT so we can get the user id on each request
server.express.use((req, res, next) => {
    const {token} = req.cookies;
    if(token) {
        const {userId} = jwt.verify(token, process.env.APP_SECRET);
        // put the userId onto the req for future requests to access
        req.userId = userId;
    }
    next();
});

// Create a middleware that populates the user on each request
server.express.use(async (req, res, next) => {
    // if they are not logged in, skip thi
    if(!req.userId) {
        return next();
    }
    const user = await db.query.user({
        where: { id: req.userId }
    }, '{ id, permissions, email, name }');
    req.user = user;
    next();
});

server.start({
    // cors: {
    //     credentials: true,
    //     origin: 'https://sick-fits-next-prod-app.herokuapp.com/'
    // }
}, deets => {
    console.log(`Server is now running on port http://localhost:${deets.port}`)
});