const express = require("express");
const app = express();
const port = process.env.PORT || 3000;
require("dotenv").config();
const validator = require("validator");
const bcrypt = require("bcrypt");
const saltRounds = 10;

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

const mongoose = require("mongoose");

mongoose
  .connect(process.env.MONGODB_LOCAL_URI)
  .then(() => console.log("successfully connected to mongodb"))
  .catch((err) => console.error("mongo connection error: ", err));

const userSchema = mongoose.Schema(
  {
    email: {
      type: String,
      required: [ true, "Email is required" ],
      unique: true,
      trim: true,
      lowercase: true, //to ensure email consistency
      validate:{
        validator: validator.isEmail,
        message: "Please enter a valid email"
      }
    },
    password: {
      type: String,
      required: true,
    },
  },
  {
    timestamps: true,
  }
);


const User = mongoose.model("User", userSchema);

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

      //secure hashing
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      const newUser = await User.create({
        email: email,
        password: hashedPassword,
      });

        res.render("secrets");
    } catch (err) {
      if (err.code === 11000) {
        return res.status(400).send("Email already registered");
      }
      res.status(500).send("Registration error");
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

    //checking for the user with the particular email and validating
      const user = await User.findOne({ email: email });
      if (!user) return res.status(401).send("invalid credentials");

      //using bcrypt to validate if the hashed passwords are the same
      const isValid = await bcrypt.compare(password , user.password);
      if (!isValid) return res.status(401).send("invalid credentials");

      res.render("secrets");

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
