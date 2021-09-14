const router = require("express").Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets");
const {
  checkUsernameExists,
  validateRoleName } = require('./auth-middleware');
const Users = require('../users/users-model');

router.post("/register",
  validateRoleName,
  (req, res, next) => {
    let user = req.body;
    const rounds = process.env.BCRYPT_ROUNDS || 8; // 2 ^ 8
    const hash = bcrypt.hashSync(user.password, rounds);
    user.password = hash;
    Users.add(user)
      .then(saved => {
        res.status(201).json(saved);
      })
      .catch(next);
  });


router.post("/login",
  checkUsernameExists,
  (req, res, next) => {
    /**
      [POST] /api/auth/login { "username": "sue", "password": "1234" }
  
      response:
      status 200
      {
        "message": "sue is back!",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
      }
  
      The token must expire in one day, and must provide the following information
      in its payload:
  
      {
        "subject"  : 1       // the user_id of the authenticated user
        "username" : "bob"   // the username of the authenticated user
        "role_name": "admin" // the role of the authenticated user
      }
     */
    function tokenBuilder(user) {
      const payload = {
        subject: user.id,
        username: user.username,
        role: user.role
      };
      const options = {
        expiresIn: '1d'
      };
      const token = jwt.sign(
        payload,
        JWT_SECRET,
        options,
      );
      return token;
    };
  });

module.exports = router;
