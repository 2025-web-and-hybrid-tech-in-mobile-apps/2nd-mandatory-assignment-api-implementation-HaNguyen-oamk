const express = require("express");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
dotenv.config();

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET_KEY || "12345abc";

let users = [];
let scores = [];

// Middleware
function authenticateToken(req, res, next) {
  const token = req.header("Authorization");
  if (!token)
    return res.status(401).json({ message: "Unauthorized, JWT token is miss" });

  jwt.verify(token.split(" ")[1], SECRET_KEY, (err, user) => {
    if (err)
      return res
        .status(401)
        .json({ message: "Unauthorized, JWT token is invalid" });

    req.user = user;
    next();
  });
}

// Signup
app.post("/signup", async (req, res) => {
  const { userHandle, password } = req.body;
  if (!userHandle || !password)
    return res.status(400).json({ message: "Invalid request body" });

  if (userHandle.length < 6 || password.length < 6)
    return res.status(400).json({
      message: "UserHandle and password have at least 6 characters",
    });

  // if (
  //   users.some((u) => u.userHandle.toLowerCase() === userHandle.toLowerCase())
  // )
  //   return res.status(400).json({ message: "User already exists" });

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ userHandle, password: hashedPassword });

  res.status(201).json({ message: "User registered successfully" });
});

// Login Endpoint
app.post("/login", async (req, res) => {
  const { userHandle, password, ...extraFields } = req.body;

  if (Object.keys(extraFields).length > 0) {
    return res
      .status(400)
      .json({ message: "Request contains unexpected fields" });
  }

  if (typeof userHandle !== "string" || typeof password !== "string") {
    return res
      .status(400)
      .json({ message: "Invalid data type for userHandle or password" });
  }

  if (!userHandle || !password)
    return res.status(400).json({ message: "Invalid request body" });

  const user = users.find(
    (u) => u.userHandle.toLowerCase() === userHandle.toLowerCase()
  );
  if (!user)
    return res
      .status(401)
      .json({ message: "Unauthorized, incorrect username or password" });

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch)
    return res
      .status(401)
      .json({ message: "Unauthorized, incorrect username or password" });

  const token = jwt.sign({ userHandle: user.userHandle }, SECRET_KEY, {
    expiresIn: "1h",
  });
  res.status(200).json({ jsonWebToken: token });
});

// Submit High Score
app.post("/high-scores", authenticateToken, (req, res) => {
  const { level, userHandle, score, timestamp } = req.body;

  if (!userHandle || !level || !score || !timestamp) {
    return res.status(400).json({ message: "Invalid request body" });
  }

  if (typeof score !== "number" || score < 0) {
    return res
      .status(400)
      .json({ message: "Score must be a positive integer" });
  }

  scores.push({ level, userHandle, score, timestamp });
  res.status(201).json({ message: "High score posted successfully" });
});

// Get High Scores
app.get("/high-scores", (req, res) => {
  const { level, page = 1 } = req.query;
  if (!level)
    return res
      .status(400)
      .json({ message: "Level query parameter is required" });

  const filteredScores = scores
    .filter((s) => s.level === level)
    .sort((a, b) => b.score - a.score);
  const paginatedScores = filteredScores.slice((page - 1) * 20, page * 20);

  res.status(200).json(paginatedScores);
});

// Server Start & Stop Functions
let serverInstance = null;

module.exports = {
  start: function () {
    serverInstance = app.listen(PORT, () => {
      console.log(`Server listening at http://localhost:${PORT}`);
    });
  },
  close: function () {
    if (serverInstance) serverInstance.close();
  },
};
