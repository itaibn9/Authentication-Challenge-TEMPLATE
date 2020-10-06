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
const INFORMATION = [{name: "admin", info: "admin info"}];
let refreshTokenArray = [];
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
        INFORMATION.push({name: req.body.name, info: `${req.body.name} info`});
        console.log(INFORMATION);
        res.status(201).send("Register success");
    } catch (error) {
        res.status(403).send();
    }


})

app.post("/users/login", async (req, res) => {
        const username = req.body.email;
        const user = USERS.find(user => user.email === username);
        if(user == null) {
            return res.status(404).send("cannot find user")
        }
        try {
        if(!await bcrypt.compare(req.body.password, user.password)){
            res.status(403).send("User or Password incorrect"); 
        }      
               const accessToken = await generateAccessToken({username: username});
                const refreshToken =  jwt.sign(user.email, NotSafeRefreshTokenSecretKey);
                refreshTokenArray.push(refreshToken);
            
        
            res.status(200).send({accessToken : accessToken, refreshToken: refreshToken, userName: user.name, isAdmin: user.isAdmin});   
    } catch (error) {
        res.status(403).send("BlBlBL");
    }
})

app.post("/users/tokenValidate", authenticateToken, async (req, res) => {
    res.status(200).send({valid: true});
})

app.post("/users/token", async (req, res) => {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.status(401).send("Refresh Token Required");
    if (!refreshTokenArray.includes(refreshToken)) return res.status(403).send("Invalid Refresh Token");
    jwt.verify(refreshToken, NotSafeRefreshTokenSecretKey, (err, user) => {
        if(err) return res.sendStatus(403);
        const accessToken = generateAccessToken({name: user.name})
        res.status(200).send({accessToken: accessToken});
    })

})

app.post("/users/logout", async (req, res) => {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.status(400).send("Refresh Token Required");
    if (!refreshTokenArray.includes(refreshToken)) return res.status(400).send("Invalid Refresh Token");
    refreshTokenArray = refreshTokenArray.filter(token => token !== req.body.token);
    res.status(204).send("User Logged Out Successfully");
})

app.get("/api/v1/information", authenticateToken, async (req, res) => {
    const info = INFORMATION.find(info => info.name === user.name); // need to check what is the body
   console.log(user);
    res.status(200).send({name: info.name, info: info.info});
})

app.get("/api/v1/users",authenticateToken,  async (req, res) => {
    if(!req.body.isAdmin) return res.send("Not Required");
    res.status(200).send({USERS: USERS});
})

// app.get("/", async (req, res) => {
//     res.send("hello");
// })



const hashingFunc = async (password) => { 
    // const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, 10);
    return hashPassword;
}


const unknownEndpoint = (req, res) => {
    res.status(404).send({ error: 'unknown endpoint' });
}

async function generateAccessToken(user) {
    console.log(user);
    return  jwt.sign(user, NotSafeAccessTokenSecretKey, {expiresIn: '10s'});
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Or undefiend or the access token
    if( token == null) return res.status(401).send("Access Token Required");

    jwt.verify(token, NotSafeAccessTokenSecretKey, function(err, user) {
        console.log(user)
        if (err) return res.status(403).send("Invalid Access Token"); // you got a token but this is no longer valid
        next(user);
    })
}

app.use(unknownEndpoint);

  module.exports = app;


  //   app.get('/', (req, res) => {

//     res.send('Hello World!');
//   })
//   app.use('/', require('./api'))