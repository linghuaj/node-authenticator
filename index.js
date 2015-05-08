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
passport.use('local-login', new LocalStrategy({
    usernameField: 'email',
    failureFlash: true
}, (email, password, callback) => {
    nodeify(async() => {
        if (!email) {
            return [false, { message: 'Invalid email.'}]
        }
        email = email.toLowerCase()
        // Lookup user by email address
        let user = await User.promise.findOne({email})
            // Show error if the email does not match any users
        if (!user) {
            return [false, {message: 'email does not match any users'}]
        }
        // Show error if the hashed password does not match the stored hash
        if (!await bcrypt.promise.compare(password, user.password)) {
            return [false, {message: 'Invalid password.'}]
        }
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
        if (await User.promise.findOne({email})) {
            return [false, {message: 'That email is already taken.'}]
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
//TODO;
//what to do if user click remember me
function getLoginInfo(req, res, next) {
    console.log("getLoginInfo ><req.body", req.body)
    let hour = 3600000
        // let rememberMe = false
    if (req.body.rememberMe && req.body.rememberMe === 'on') {
        req.session.cookie.maxAge = 14 * 24 * hour
    }

    next()
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
app.post('/login', getLoginInfo, passport.authenticate('local-login', {
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