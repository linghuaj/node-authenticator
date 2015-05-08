let express = require('express')
let bodyParser = require('body-parser')
let cookieParser = require('cookie-parser')
let session = require('express-session')
let passport = require('passport')
let LocalStrategy = require('passport-local').Strategy
let bcrypt = require('bcrypt')
let nodeify = require('bluebird-nodeify')
let flash = require('connect-flash')
let mongoose = require('mongoose')
let User = require('./user')
    // let morgan = require('morgan')
require('songbird')
mongoose.connect('mongodb://127.0.0.1:27017/social-authenticator')

// const NODE_ENV = process.env.NODE_ENV || 'dev'
const PORT = process.env.PORT || 8000
const SALT = bcrypt.genSaltSync(10)

let app = express()
app.use(flash())
// Read cookies, required for sessions
app.use(cookieParser('ilovethenodejs'))
// Get POST/PUT body information (e.g., from html forms like login)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({
    extended: true
}))

   let userConst = {
        email: 'foo@foo.com',
        password: bcrypt.hashSync('asdf', SALT)
    }


// In-memory session support, required by passport.session()
// http://passportjs.org/guide/configure/
app.use(session({
    secret: 'ilovethenodejs',
    resave: true,
    saveUninitialized: true
}))

// Use the passport
// middleware to enable passport
app.use(passport.initialize())

// Enable passport persistent sessions
app.use(passport.session())

//we never use this though
passport.use('local-simple', new LocalStrategy({
    // Use "email" field instead of "username"
    usernameField: 'email',
    // We'll need this later
    failureFlash: true
}, (email, password, callback) => {
	// let userConst = {
	// 	email: 'foo@foo.com',
	// 	password: bcrypt.hashSync('asdf', SALT)
	// }

    nodeify(async() => {
        if (email !== userConst.email) {
            return [false, {
                message: 'Invalid username'
            }]
        }

        if (!await bcrypt.promise.compare(password, userConst.password)) {
            return [false, {
                message: 'Invalid password'
            }]
        }
        //after you return
        //it becomes req.user
        //otherwise you won't have anything
        return userConst

        // Use spread option when returning multiple values
        // so a callback gets convert from [1,2] => callback(null, 1, 2)
        // without spread:true, it becomes   [1, 2] => callback(null, [1, 2])
        // https://gist.github.com/vanessachem/3ba92e73ff5d21d696b9
    }(), callback, {
        spread: true
    })
}))


passport.use('local-login', new LocalStrategy({
    // Use "email" field instead of "username"
    usernameField: 'email',
    // We'll need this later
    failureFlash: true
}, (email, password, callback) => {
    nodeify(async() => {
      if (!email) return [false, {message: 'Invalid email.'}]
      email = email.toLowerCase()
      // Lookup user by email address
      let user = await User.findOne({email}).exec()
      // Show error if the email does not match any users
      if (!user) return [false, {message: 'email does not match any users'}]
      // Show error if the hashed password does not match the stored hash
      if (!await bcrypt.promise.compare(password, user.password)) {
        return [false, {message: 'Invalid password.'}]
      }
      // Return value will be set to req.user
      return user
    }(), callback, {
        spread: true
    })
}))


passport.use('local-signup', new LocalStrategy({
    // Use "email" field instead of "username"
    usernameField: 'email'
}, (email, password, callback) => {
    nodeify(async() => {
        email = (email || '').toLowerCase()
        // Is the email taken?
        if (await User.findOne({
            email
        }).exec()) {
            return [false, {
                message: 'That email is already taken.'
            }]
        }

        // create the user
        let user = new User()
        user.email = email
        // Use a password hash instead of plain-text
        user.password = await bcrypt.promise.hash(password, SALT)
        // console.log(">< user saved")
        return await user.save()

    }(), callback, {
        spread: true
    })
}))

passport.serializeUser(function(user, callback) {
    console.log(">< user", user)
    // Use email since id doesn't exist
    callback(null, user)
})

passport.deserializeUser(function(id, callback) {
    // return the hardcoded user

    callback(null, userConst)
})



// start server
app.listen(PORT, () => console.log(`Listening @ http://127.0.0.1:${PORT}`))

// And add the following just before app.listen
// Use ejs for templating, with the default directory /views
app.set('view engine', 'ejs')



// And add your root route after app.listen
app.get('/', (req, res) => res.render('index.ejs', {
    message: req.flash('error')
}))
// And add your root route after app.listen
app.get('/profile', (req, res) => res.render('profile.ejs', {}))

// process the login form
app.post('/login', passport.authenticate('local-login', {
    successRedirect: '/profile',
    failureRedirect: '/',
    failureFlash: true
}))

// process the signup form
app.post('/signup', passport.authenticate('local-signup', {
    successRedirect: '/profile',
    failureRedirect: '/',
    failureFlash: true
}))