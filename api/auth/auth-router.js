const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const router = require('express').Router()
const User = require('../users/users-model.js')

const { BCRYPT_ROUNDS, JWT_SECRET } = require('../../config')

router.post('/register', (req, res, next) => {
  let user = req.body

  // bcrypting the password before saving
  const hash = bcrypt.hashSync(user.password, BCRYPT_ROUNDS)
  // never save the plain text password in the db
  user.password = hash

  User.add(user)
    .then(saved => {
      res.status(201).json({ message: `Great to have you, ${saved.username}` })
    })
    .catch(next) // our custom err handling middleware in server.js will trap this
})

router.post('/login', (req, res, next) => {
  let { username, password } = req.body

  User.findBy({ username })
    .then(([user]) => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = buildToken(user)
        res.status(200).json({ message: `Welcome back ${user.username}...`, token })
      } else {
        next({ status: 401, message: 'Invalid Credentials' })
      }
    })
    .catch(next)
})

function buildToken(user){
  const payload = {
    //the subject is going to be essential in every payload and it is basically what the token is about!
    subject: user.id,
    username: user.username,
    role: user.role,
  }
  const options = {
    expiresIn: '1d',
  }
  return jwt.sign(payload, JWT_SECRET, options)
  //the 2nd thing inside of .sign is a secret string that, it others found out what the string is, they could use it to create other tokens. It should NOT BE HARDCODED
}

module.exports = router
