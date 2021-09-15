const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets");
const User = require('../users/users-model');

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return next({
    message: 'Token required',
    status: 401
  });
  jwt.verify(
    token,
    JWT_SECRET,
    (err, decoded) => {
      if (err) return next({
        message: 'Token invalid',
        status: 401
      });
      req.decodedJwt = decoded;
      next();
    }
  );
};

const only = role_name => (req, res, next) => {
  const { decodedJwt } = req;
  if (decodedJwt.role_name === role_name) {
    next();
  } else {
    next({
      message: 'This is not for you',
      status: 403
    });
  }
};


const checkUsernameExists = async (req, res, next) => {
  try {
    const { username } = req.body;
    const exist = await User.findBy({ username });
    if (!exist) {
      next({
        message: 'Invalid credentials',
        status: 401
      });
    } else {
      next();
    }
  } catch (err) {
    next(err);
  }
};

const validateRoleName = (req, res, next) => {

  // const { role_name } = req.body;
  // const validRole = (role_name) => {
  //   return role_name ? (typeof role_name === "string" ? true : false) : false;
  // };
  // console.log('req', req.body);
  // if (!role_name || role_name.trim() === '') {
  //   req.body.role_name = 'student';
  //   next();
  // } else if (validRole(role_name)) {
  //   if (role_name.trim() === 'admin') {
  //     next({
  //       message: 'Role name can not be admin',
  //       status: 422
  //     });
  //   } else if (role_name.length.trim() > 32) {
  //     next({
  //       message: 'Role name can not be longer than 32 chars',
  //       status: 422
  //     });
  //   } else {
  //     req.body.role_name = role_name;
  //     next();
  //   }
  // } // why does this work?
  const { role_name } = req.body;
  const validRole = (role_name) => {
    return role_name ? (typeof role_name === "string" ? true : false) : false;
  };

  if (!req.body.role_name || req.body.role_name.trim() === "") {
    req.body.role_name = "student";
    next();
  } else if (validRole(role_name)) {
    req.body.role_name = role_name.trim();
    if (req.body.role_name === "admin") {
      next({ status: 422, message: "Role name can not be admin" });
    } else if (req.body.role_name.length > 32) {
      next({
        status: 422,
        message: "Role name can not be longer than 32 chars",
      });
    }
    next();
  }
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
