require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.use(express.json());

// Models
const User = require("./models/User");

app.get("/", (req, res) => {
  res.status(200).json({message: "Hello Dev!"});
})

// private route
app.get('/user/:id', checkToken, async (req, res) => {
  const id = req.params.id;

  // check if user exists
  const user = await User.findById(id, "-password");

  if(!user) {
    res.status(404).json({message: "Usuário não encontrado!"});
  }

  res.status(200).json({user});
})

// middleware
function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if(!token) {
    return res.status(401).json({message: "Acesso Negado!"});
  }

  try {
    const secret = process.env.SECRET;
    jwt.verify(token, secret);

    next();
  } catch (err) {
    res.status(400).json({message: "Token inválido!"});
  }
}

// Register User
app.post("/auth/register", async(req, res) => {
  const {name, email, password, confirmpassword} = req.body;

  // validations
  if (!name) {
    return res.status(422).json({message: "O nome é obrigatório!"});
  }
  if (!email) {
    return res.status(422).json({message: "O email é obrigatório!"});
  }
  if (!password) {
    return res.status(422).json({message: "A senha é obrigatória!"});
  }
  if(password !== confirmpassword) {
    res.status(422).json({message: "As senhas estão diferentes!"});
  }

  // check if user exists
  const userExists = await User.findOne({email: email});

  if(userExists) {
    res.status(422).json({message: "Email já cadastrado, por favor utilizar outro email!"});
  }

  // create password
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  // create user
  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save();
    res.status(201).json({message: "Usuário criado com sucesso!"});
  } catch (err) {
    console.log(err);
    res.status(500).json({message: "Aconteceu algo no servidor, tente mais tarde", err});
  }
});

// login user
app.post("/auth/user", async (req, res) => {
  const {email, password} = req.body;

  // validations
  if (!email) {
    return res.status(422).json({message: "O email é obrigatório!"});
  }
  if (!password) {
    return res.status(422).json({message: "A senha é obrigatória!"});
  }

  // check if user exists
  const user = await User.findOne({email: email});

  if(!user) {
    res.status(404).json({message: "Usuário não encontrado!"});
  }

  // check if password match
  const checkPassword = await bcrypt.compare(password, user.password);

  if(!checkPassword) {
    res.status(422).json({message: "Senha inválida!"});
  }

  try {
    const secret = process.env.secret;

    const token = jwt.sign({
      id: user._id
    }, secret,)
    res.status(200).json({message: "Autenticação realizada com sucesso1", token});
  } catch (err) {
    console.log(err);
    res.status(500).json({message: "Aconteceu algo no servidor, tente mais tarde", err});
  }
})

const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;


mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.o9okb.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`)
.then(() => {
  app.listen(3000, () => {
    console.log("Database connceted!");
    console.log("Server Online!");
  })
  
}).catch((err) => console.log(err));
