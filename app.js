const express = require("express");
const app = express();
const port = process.env.PORT || 3000;
require("dotenv").config();


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
      required: true,
      unique: true,
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
      const { username, password } = req.body;

      // const newUser = new User({
      //     email: username,
      //     password: password
      // })

      // newUser.save()

      const newUser = await User.create({
        email: username,
        password: password,
      });

      !newUser
        ? res.status(400).send("no new user was made")
        : res.render("secrets");
    } catch (err) {
      res.status(500).send("server creation error: ", err);
    }
  });

app
  .route("/login")

  .get((req, res) => {
    res.render("login");
  })

  .post(async (req, res) => {
    try {
      const { username, password } = req.body;

      //  login authentication
      //   if the stored email matches the written email ,it checks if the password is the same as the stored password
      const foundUser = await User.findOne({ email: username });

      // if (foundUser){
      //   if (foundUser.password === password){
      //       res.render("secrets")
      //   }
      // }

      foundUser && foundUser.password === password
        ? res.render("secrets")
        : res.status(401).send("Details entered are wrong, try again");
    } catch (err) {
      res.status(500).send("login server error : ", err);
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
