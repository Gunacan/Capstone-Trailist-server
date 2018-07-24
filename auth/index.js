const express = require('express')
const Joi = require('joi')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const db = require('../db/connection')
const users = db.get('users')

// users.index('email')
users.createIndex('email', { unique: true })

const router = express.Router()

const signupSchema = Joi.object().keys({
    firstName: Joi.string().alphanum().min(2).max(30).required(),
    lastName: Joi.string().alphanum().min(2).max(30).required(),
    email: Joi.string().email().required(),
    password: Joi.string().trim().min(8).required()
    // password: Joi.string().regex(/^[a-zA-Z0-9]{8,30}$/).required()
})

const loginSchema = Joi.object().keys({
    email: Joi.string().email().required(),
    password: Joi.string().trim().min(8).required()
    // password: Joi.string().regex(/^[a-zA-Z0-9]{8,30}$/).required()
})

router.get('/', (req, res) => {
    res.json({
        message: 'hello'
    })
})

router.post('/signup', (req, res, next) => {
    const result = Joi.validate(req.body, signupSchema)
    if  (result.error === null) {
        users.findOne({
            email: req.body.email
        }).then(user => {
            if (user) {
                const error = new Error('This email adress already exists!')
                res.status(409)
                next(error)
            } else {
                bcrypt.hash(req.body.password.trim(), 12).then(hashedPassword => {
                    // res.json({ hashedPassword })
                    const newUser = {
                        firstName: req.body.firstName,
                        lastName: req.body.lastName,
                        email: req.body.email,
                        password: hashedPassword
                    }
                    users.insert(newUser).then(insertedUser => {
                        delete(insertedUser.password)
                        res.json(insertedUser)
                        // res.json({
                        //     _id: insertedUser._id,
                        //     email: insertedUser.email,
                        //     name: insertedUser.firstName + ' ' +  insertedUser.lastName
                        // })
                    })
                })
            }
        })
    } else {
        res.status(406)
        next(result.error)
    }
})

function noMatchRespond(res, next) {
    res.status(409)
    const error = new Error('Your login information does not match!')
    next(error)
}

router.post('/login', (req, res, next) => {
    const result = Joi.validate(req.body, loginSchema)
    if  (result.error === null) {
        users.findOne({
            email: req.body.email
        }).then(user => {
            if (user) {
                // console.log('a:', req.body.password, 'b:', user.password)
                bcrypt.compare(req.body.password, user.password).then(result => {
                    if (result) {
                        const payload = {
                            _id : user._id,
                            email: user.email
                        }
                        // console.log('oooooooooooo:', process.env.TOKEN_SECRET)

                        jwt.sign(payload, process.env.TOKEN_SECRET, { expiresIn: '1h' }, (err, token) => {
                            if (err) {
                                noMatchRespond(res, next)
                            } else {
                                res.json({ token })
                            }
                        } )
                    } else {
                        noMatchRespond(res, next)
                    }
                })
            } else {
                noMatchRespond(res, next)
            }
        })
    } else {
        noMatchRespond(res, next)
    }
}) 

module.exports = router 