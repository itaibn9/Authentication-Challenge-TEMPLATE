/* write your server code here */
const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
app.use(express.json());

const USERS = [
    {email: "admin@email.com",
     name: "admin",
     password:"$2b$10$TPrt/eFC4jYgdb1B2cUrjO4LtcdcViLFurj9slRhExoD5ECUUQylC",
     isAdmin: true
    }];
const INFORMATION = [{email: "admin@email.com", info: "admin info"}];
let REFRESHTOKENS  = [];
const NotSafeAccessTokenSecretKey = "8d2db1dd2f2eab45b5f7a0db486a6aed84cf802502eb83928dcfcd95e1459544192bf0be2e5549c4fce0dc26fa0608dfcae5762683087f34aed4afe111acf5e4";
const NotSafeRefreshTokenSecretKey = 'c9120e104f5a645406ea8575d63d19ed7f12a9186021b589a7b4c2aecee152e827beda1879b0650ad59730d30b77b4efa1497a1250f39d18ab0c3c3732a9722c';


app.post("/users/register", async (req, res) => {
    req.body.isAdmin ? null : req.body.isAdmin = false;
    if(!req.body.email || !req.body.name || !req.body.password) {
        res.status(403).send("Fill properly")
        }
    if(USERS.find(user => user.name === req.body.name)) return res.status(409).send("user already exists");
        try { 
        req.body.password = await hashingFunc(req.body.password);
        const user = {email: req.body.email , name: req.body.name, password: req.body.password, isAdmin: req.body.isAdmin};
        USERS.push(req.body);
        INFORMATION.push({email: req.body.email, info: `${req.body.name} info`});
        res.status(201).send("Register success");
    } catch (error) {
        res.status(403).send();
    }


})

app.post("/users/login", async (req, res) => {
        const username = req.body.email;
        const userDetails = USERS.find(user => user.email === username);
        if(userDetails == null) {
            return res.status(404).send("cannot find user")
        }
        try {
        if(!await bcrypt.compare(req.body.password, userDetails.password)){
            res.status(403).send("User or Password incorrect"); 
        }      
               const accessToken = await generateAccessToken({name: username});
                const refreshToken =  jwt.sign(userDetails.email, NotSafeRefreshTokenSecretKey);
                REFRESHTOKENS.push(refreshToken);
            
        
            res.status(200).send({accessToken : accessToken, refreshToken: refreshToken, email: userDetails.email, name: userDetails.name, isAdmin: userDetails.isAdmin});   
    } catch (error) {
        res.status(403).send();
    }
})

app.post("/users/tokenValidate", authenticateToken, async (req, res) => {
    res.status(200).send({valid: true});
})

app.post("/users/token", async (req, res) => {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.status(401).send("Refresh Token Required");
    if (!REFRESHTOKENS.includes(refreshToken)) return res.status(403).send("Invalid Refresh Token");
    jwt.verify(refreshToken, NotSafeRefreshTokenSecretKey, async (err, user) => {
        if(err) return res.sendStatus(403);
        const accessToken = await generateAccessToken({name: user})
        res.status(200).send({accessToken: accessToken});
    })

})

app.post("/users/logout", async (req, res) => {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.status(400).send("Refresh Token Required");
    if (!REFRESHTOKENS.includes(refreshToken)) return res.status(400).send("Invalid Refresh Token");
    REFRESHTOKENS  = REFRESHTOKENS.filter(token => token !== req.body.token);
    res.status(200).send("User Logged Out Successfully");
})

app.get("/api/v1/information", authenticateToken, async (req, res) => {
    const info = INFORMATION.find(inf => inf.email === req.user.name); // need to check what is the body
    res.status(200).send([{name: info.email, info: info.info}]);
})

app.get("/api/v1/users", authenticateToken, async (req, res) => {
    try {
    const adminValidation = USERS.find(i => i.email === req.user.name);
    if(!adminValidation.isAdmin) return res.send("Not Required");
    res.status(200).send(USERS);
    } catch (error) {
        res.status(500).send(adminValidation)
    }
})

app.options("/", async (req, res) => {
    if(req.headers['authorization'] == null){
     res.status(200).send([
         {method: "post", path: "/users/register", description: "Register, Required: email, name, password",
          example: { body: { email: "user@email.com", name: "user", password: "password" } } },
         {method: "post", path: "/users/login", description: "Login, Required: valid email and password",
         example: { body: { email: "user@email.com", password: "password" } } }]);
     } else {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        jwt.verify(token, NotSafeAccessTokenSecretKey, (err, user) => {
            if(err) return res.status(200).send([
                { method: "post", path: "/users/register", description: "Register, Required: email, name, password"},
                { method: "post", path: "/users/login", description: "Login, Required: valid email and password"},
                { method: "post", path: "/users/token", description: "Renew access token, Required: valid refresh token"}
            ]);
            const adminValidation = USERS.find(i => i.email === user.name);
            if(adminValidation.isAdmin){
                 res.status(200).send([
                { method: "post", path: "/users/register", description: "Register, Required: email, name, password"},
                { method: "post", path: "/users/login", description: "Login, Required: valid email and password"},
                { method: "post", path: "/users/token", description: "Renew access token, Required: valid refresh token"},
                { method: "post", path: "/users/tokenValidate", description: "Access Token Validation, Required: valid access token"},
                { method: "get", path: "/api/v1/information", description: "Access user's information, Required: valid access token"},
                { method: "post", path: "/users/logout", description: "Logout, Required: access token"},
                { method: "get", path: "api/v1/users", description: "Get users DB, Required: Valid access token of admin user"},
              ]) 
            } else {
            res.status(200).send([{ method: "post", path: "/users/register", description: "Register, Required: email, name, password"},
            { method: "post", path: "/users/login", description: "Login, Required: valid email and password"},
            { method: "post", path: "/users/token", description: "Renew access token, Required: valid refresh token"},
            { method: "get", path: "/api/v1/information", description: "Access user's information, Required: valid access token"},
            { method: "post", path: "/users/logout", description: "Logout, Required: access token"},
            { method: "post", path: "/users/tokenValidate", description: "Access Token Validation, Required: valid access token"},
          ]);}
        })
     }
         
})


const hashingFunc = async (password) => { 
    // const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, 10);
    return hashPassword;
}


const unknownEndpoint = (req, res) => {
    res.status(404).send({ error: 'unknown endpoint' });
}

async function generateAccessToken(user) {
    // if(typeof user == "string")
    // user = JSON.stringify(user)
    return jwt.sign(user, NotSafeAccessTokenSecretKey, {expiresIn: 10});
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    console.log(authHeader);
    const token = authHeader && authHeader.split(' ')[1]; // Or undefiend or the access token
    console.log(token);
    if(token == null) return res.status(401).send("Access Token Required");

    jwt.verify(token, NotSafeAccessTokenSecretKey,(err, user) => {
        console.log(err);
        if (err) return res.status(403).send("Invalid Access Token"); // you got a token but this is no longer valid
        req.user = user;
        next();
    })
}


app.use(unknownEndpoint);

  module.exports = app;


  //   app.get('/', (req, res) => {

//     res.send('Hello World!');
//   })
//   app.use('/', require('./api'))