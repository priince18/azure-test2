require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const sql = require("mssql");
const path = require("path");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ✅ Azure SQL config
const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  server: process.env.DB_SERVER,
  port: 1433,
  options: {
    encrypt: true,
    trustServerCertificate: false
  },
  pool: {
    max: 10,
    min: 0,
    idleTimeoutMillis: 30000
  }
};

// ✅ Helper: get DB pool safely
async function getPool() {
  return await sql.connect(dbConfig);
}

// ---------- ROUTES ----------

// Signup page
app.get("/", (req, res) => {
  res.sendFile(path.join(process.cwd(), "views", "signup.html"));
});

app.get("/signup", (req, res) => {
  res.sendFile(path.join(process.cwd(), "views", "signup.html"));
});

// Signup logic
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const pool = await getPool();

    const check = await pool.request()
      .input("email", sql.VarChar, email)
      .query("SELECT id FROM users WHERE email=@email");

    if (check.recordset.length > 0) {
      return res.send("User exists <a href='/login'>Login</a>");
    }

    const hash = await bcrypt.hash(password, 10);

    await pool.request()
      .input("name", sql.VarChar, name)
      .input("email", sql.VarChar, email)
      .input("password", sql.VarChar, hash)
      .query(`
        INSERT INTO users (name, email, password)
        VALUES (@name, @email, @password)
      `);

    res.redirect("/login");
  } catch (err) {
    res.status(500).send("Signup error: " + err.message);
  }
});

// Login page
app.get("/login", (req, res) => {
  res.sendFile(path.join(process.cwd(), "views", "login.html"));
});

// Login logic
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const pool = await getPool();

    const result = await pool.request()
      .input("email", sql.VarChar, email)
      .query("SELECT * FROM users WHERE email=@email");

    if (result.recordset.length === 0) {
      return res.send("User not found");
    }

    const user = result.recordset[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.send("Wrong password");
    }

    res.send(`
      <h2>Login Successful</h2>
      <p>Name: ${user.name}</p>
      <p>Email: ${user.email}</p>
    `);
  } catch (err) {
    res.status(500).send("Login error: " + err.message);
  }
});

// Azure PORT
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("🚀 App running on port", PORT);
});
