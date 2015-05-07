// user.js
let mongoose = require('mongoose')
let bcrypt = require('bcrypt')

let userSchema = mongoose.Schema({
    email: String,
    password: String
})






module.exports = mongoose.model('User', userSchema)