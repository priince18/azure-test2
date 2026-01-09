require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const sql = require("mssql");
const path = require("path");

const app = express();
app.use(express.urlencoded({ extended: true })); // 👈 for form data
app.use(express.json());

// Azure SQL config
const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  server: process.env.DB_SERVER,
  options: {
    encrypt: true
  }
};

// Connect DB
sql.connect(dbConfig)
  .then(() => console.log("✅ DB Connected"))
  .catch(err => console.log("❌ DB Error:", err));

// ---------- ROUTES ----------

// Home → Signup
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "signup.html"));
});

// Signup page
app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "signup.html"));
});

// Signup logic
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  const check = await sql.query`
    SELECT id FROM users WHERE email=${email}
  `;

  if (check.recordset.length > 0) {
    return res.send("User already exists. <a href='/login'>Login</a>");
  }

  const hash = await bcrypt.hash(password, 10);

  await sql.query`
    INSERT INTO users (name, email, password)
    VALUES (${name}, ${email}, ${hash})
  `;

  res.redirect("/login"); // 👈 go to login
});

// Login page
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "login.html"));
});

// Login logic
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const result = await sql.query`
    SELECT * FROM users WHERE email=${email}
  `;

  if (result.recordset.length === 0) {
    return res.send("User not found");
  }

  const user = result.recordset[0];
  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    return res.send("Wrong password");
  }

  // Show profile
  res.send(`
    <h2>Login Successful</h2>
    <p><b>ID:</b> ${user.id}</p>
    <p><b>Name:</b> ${user.name}</p>
    <p><b>Email:</b> ${user.email}</p>
  `);
});

// Start server
app.listen(process.env.PORT, () => {
  console.log("🚀 Server running on port", process.env.PORT);
});
