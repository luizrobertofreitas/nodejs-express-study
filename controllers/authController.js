require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../models/user');
const jwt = require('jsonwebtoken');

const router = express.Router();

function generateToken(params = {}) {
  return jwt.sign({ id: params.id }, process.env.JWT_MD5_HASH, {
    expiresIn: 85400
  });
}

router.post('/register', async (req, res) => {
  try {

    const { email } = req.body;

    if (await User.findOne({ email }))
      return res.status(400).send({ "error" : "User already exists" });

    const user = await User.create(req.body);

    user.password = undefined;

    const token = generateToken({ id: user.id });

    return res.status(201).send({ user, token });

  } catch (err) {
    console.log(err);
    return res.status(400).send({ error: "Registration failed" });
  }
});

router.post('/authenticate', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select('+password');

    if (!user)
      return res.status(404).send({ error: "User not found" });

    if (!await bcrypt.compare(password, user.password))
      return res.status(401).send({ error: "Invalid password" });
    
    user.password = undefined;

    const token = generateToken({ id: user.id });

    return res.send({ user, token });
  } catch (err) {
    console.log(err);
    return res.status(500).send({ error: err });
  }
});

module.exports = app => app.use("/auth", router);