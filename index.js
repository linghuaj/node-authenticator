let express = require('express')
let bodyParser = require('body-parser')
let cookieParser = require('cookie-parser')
let session = require('express-session')
let passport = require('passport')
let LocalStrategy = require('passport-local').Strategy
let bcrypt = require('bcrypt')
let nodeify = require('bluebird-nodeify')
let mongoose = require('mongoose')
let flash = require('connect-flash')

let User = require('./models/user')

require('songbird')
mongoose.connect('mongodb://127.0.0.1:27017/social-authenticator')

const PORT = process.env.PORT || 8000
const SALT = bcrypt.genSaltSync(10)

let app = express()

// And add the following just before app.listen
// Use ejs for templating, with the default directory /views
app.set('view engine', 'ejs')

app.use(flash())
// Read cookies, required for sessions
app.use(cookieParser('ilovethenodejs'))
// Get POST/PUT body information (e.g., from html forms like login)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({
    extended: true
}))

// In-memory session support, required by passport.session()
// http://passportjs.org/guide/configure/
app.use(session({
    secret: 'ilovethenodejs',
    resave: true,
    saveUninitialized: true
}))

// Use the passport middleware to enable passport
app.use(passport.initialize())

// Enable passport persistent sessions
app.use(passport.session())

// start server
app.listen(PORT, () => console.log(`Listening @ http://127.0.0.1:${PORT}`))

//gist for simple strategy: https://gist.github.com/vanessachem/9293b234ea92d63b73d8
function extendCookieExpire(req) {
    if (req.body.remember) {
        req.session.cookie.expires = false
    } else {
        req.session.cookie.maxAge = 1000
    }
    return req
}

passport.use('local-login', new LocalStrategy({
    usernameField: 'email',
    failureFlash: true,
    passReqToCallback: true //how to access req in passport cb
}, (req, email, password, callback) => {
    nodeify(async() => {
        if (!email) {
            return [false, {
                message: 'Invalid email.'
            }]
        }
        email = email.toLowerCase()
        // Lookup user by email address
        let user = await User.promise.findOne({
                email
            })
            // Show error if the email does not match any users
        if (!user) {
            return [false, {
                message: 'email does not match any users'
            }]
        }
        // Show error if the hashed password does not match the stored hash
        if (!await bcrypt.promise.compare(password, user.password)) {
            return [false, {
                message: 'Invalid password.'
            }]
        }
        //we can alter the req here, or a middlewhere after this strategy.
        extendCookieExpire(req)
        //how to access req.
        //generate a tokcen and save to cookie
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
        if (await User.promise.findOne({
            email
        })) {
            return [false, {
                message: 'That email is already taken.'
            }]
        }
        // create the user
        let user = new User()
        user.email = email
        // Use a password hash instead of plain-text
        user.password = await bcrypt.promise.hash(password, SALT)
        return await user.save()
    }(), callback, {
        spread: true
    })
}))

//why serialize
//when saved to session, it's only going to save userid in the session store
passport.serializeUser(function(user, callback) {
    console.log(">< serialize user")
    // Use email since id doesn't exist
    callback(null, user.id)
})

//why deserialize
passport.deserializeUser(function(id, callback) {
    console.log(">< deserialize id", id)
    nodeify(async() => {
        // https://gist.github.com/vanessachem/71638f362b4405551336
        let user = await User.promise.findById(id)
        console.log(">< user deserialize", user)
        return user
    }(), callback, {
        spread: true
    })

})

function isLoggedIn(req, res, next) {
    //passport handled
    //comes with pasport by default
    if (req.isAuthenticated()) return next()

    res.redirect('/')
}

// routes
app.get('/', (req, res) => res.render('index.ejs', {
    message: req.flash('error')
}))
app.get('/profile', isLoggedIn, (req, res) => {
    return res.render('profile.ejs', {
        email: req.user.email,
        id: req.user.id
    })
})
app.get('/logout', function(req, res) {
    req.logout()
    res.redirect('/')
})

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