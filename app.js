const express = require("express");
const app = express();
const port = process.env.PORT || 3000;
require("dotenv").config();
const validator = require("validator");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose").default; //for local auth
const GoogleStrategy = require("passport-google-oauth20").Strategy; //for google auth
const cookieParser = require("cookie-parser");
const flash = require("connect-flash"); //for flash messages



app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false, // doesn't save unchanged sessions
    saveUninitialized: false, // doesn't create if empty
    cookie:{
      httpOnly: true, //prevents client side js from accessing the cookie
      maxAge: 1000 * 60 * 60 * 24, //cookie expires after 1 day
    }
  }),
);

app.use(passport.initialize()); //initializes passport
app.use(passport.session()); //manages persistent login sessions

app.use(cookieParser());
app.use((req,res,next) =>{
  res.locals.cookieConsent = req.cookies.cookieConsent; //global variable to check if user has given cookie consent, accessible in all views
  next();
})

app.use(flash()); //for flash messages
app.use((req, res, next) => {
  res.locals.success = req.flash("success");
  res.locals.error = req.flash("error");
  next();
});

const mongoose = require("mongoose");

mongoose
  .connect(process.env.MONGODB_LOCAL_URI)
  .then(() => console.log("successfully connected to mongodb"))
  .catch((err) => console.error("mongo connection error: ", err));

const userSchema = mongoose.Schema(
  {
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      trim: true,
      lowercase: true, //to ensure email consistency
      validate: {
        validator: validator.isEmail,
        message: "Please enter a valid email",
      },
    },
    googleId: {
      //for google auth
      type: String,
      unique: true,
      sparse: true, //allows multiple null values for googleId since not all users will have it (only google auth users)
    },
  },
  {
    timestamps: true,
  },
);

userSchema.plugin(passportLocalMongoose, { usernameField: "email" }); // enabled to hash and salt paasswords and save users into the db. also uses email as username

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy()); //passport local strategy - auth user using their username and password
passport.serializeUser(User.serializeUser()); //creates a cookie and stores users info
passport.deserializeUser(User.deserializeUser()); //removes cookie and retrieves users info

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo", //to get user info from google profile
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const user = await User.findOneAndUpdate(
          { googleId: profile.id }, //finds user with googleId if exists
          {
            googleId: profile.id, //stores googleId from google profile
            email: profile.emails[0].value, //stores email from google profile
          },
          { upsert: true, new: true }, //creates new user if not found and returns the updated document
        );

        return done(null, user); //successful authentication, returns user info to serializeUser
      } catch (err) {
        return done(err, null); //error during authentication, returns error to serializeUser
      }
    },
  ),
);

app.get("/", (req, res) => {
  res.render("home");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] }), //initiates google auth and requests access to user's profile and email
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    failureRedirect: "/login", //redirects to login page if authentication fails
  }),
  (req, res) => {
    req.flash("success", "Login successful!"); //sets success flash message
    res.redirect("/secrets"); //redirects to secrets page if authentication is successful
  },
);

app.post("/accept-cookies", (req, res) =>{
  res.cookie("cookieConsent", "true",{
    httpOnly: false, //allows client side js to access the cookie since we need to check cookie consent in the frontend
    maxAge: 1000 * 60 * 60 * 24 * 365, //cookie expires after 1 year
  });
  res.sendStatus(200);
});

app
  .route("/register")
  .get((req, res) => {
    res.render("register");
  })

  .post(async (req, res) => {
    try {
      const { email, password } = req.body;

      await User.register({ email: email }, password); //registers user and hashes password

      passport.authenticate("local")(req, res, () => { //authenticates user using local strategy if registration is successful and redirects to secrets page
        req.flash("success", "Registration successful!"); //sets success flash message
        res.redirect("/secrets");
      });
    } catch (err) {
      if (err.code === 11000) {
        req.flash("error", "Email already registered");
        return res.redirect("/register");
      }
      req.flash("error", "Registration error");
      return res.redirect("/register");
    }
  });

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    return res.render("secrets") //renders secrets page if user is authenticated
  } 

  req.flash("error", "Please log in to view secrets"); //sets error flash message if user is not authenticated
  res.redirect("/login");
  
});

app
  .route("/login")

  .get((req, res) => {
    res.render("login");
  })

  .post(
    passport.authenticate("local", {
      //handles everything related to authentication - checks if user exists, compares password, etc
      failureRedirect: "/login",
      failureFlash: true, //enables flash messages on authentication failure
    }),
    (req, res) => {
      req.flash("success", "Login successful!"); //sets success flash message
      res.redirect("/secrets");
    }
  );

app
  .route("/submit")
  .get((req, res) => {
    if(req.isAuthenticated()){
      return res.render("submit");
    }
      req.flash("error", "Please log in to submit secrets");
      res.redirect("/login");
  })

  .post((req, res) => {
    const secret = req.body;
  });

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      console.error("logout error: ", err);
      return next(err); //moves to the next middleware
    }
    req.flash("success", "Logged out successfully!"); //sets success flash message
    res.redirect("/");
  });
});

app.listen(port, () => console.log(`secret app is live at port ${port}`));
