const express = require("express");
const app = express();
const port = process.env.PORT || 3000;
require("dotenv").config();
const validator = require("validator");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose").default;


app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false, // doesn't save unchanged sessions
    saveUninitialized: false, // doesn't create if empty
  })
);

app.use(passport.initialize()); //initializes passport
app.use(passport.session()); //manages persistent login sessions

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
  },
  {
    timestamps: true,
  }
);

userSchema.plugin(passportLocalMongoose, { usernameField: "email" }); // enabled to hash and salt paasswords and save users into the db. also uses email as username

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy()); //passport local strategy - auth user using their username and password
passport.serializeUser(User.serializeUser()); //creates a cookie and stores users info
passport.deserializeUser(User.deserializeUser()); //removes cookie and retrieves users info 

app.get("/", (req, res) => {
  res.render("home");
});

app
  .route("/register")
  .get((req, res) => {
    res.render("register");
  })

  .post(async (req, res) => {
    try {
      const { email, password } = req.body;

      const newUser = await User.register({ email: email }, password); //registers user and hashes password

      passport.authenticate("local")(req, res, () => { //authenticates user using local strategy if registration is successful and redirects to secrets page
        res.redirect("/secrets");
      });
     
    } catch (err) {
      if (err.code === 11000) {
        return res.status(400).send("Email already registered");
      }
      res.status(500).send("Registration error");
    }
  });

app.get("/secrets", (req, res) => { 
  if (req.isAuthenticated()) {
    res.render("secrets"); //renders secrets page if user is authenticated
  } else {
    res.redirect("/login");
  }
});

app
  .route("/login")

  .get((req, res) => {
    res.render("login");
  })

  .post(async (req, res) => {
    try {
      const { email, password } = req.body;

     const user = await User.create({
      email: email,
      password: password
     });

      // res.render("secrets");
    } catch (err) {
      res.status(500).send("login server error");
    }
  });

app
  .route("/submit")
  .get((req, res) => {
    res.render("submit");
  })

  .post((req, res) => {
    const secret = req.body;
  });

app.get("/logout", (req, res) => {});

app.listen(port, () => console.log(`secret app is live at port ${port}`));
