const express = require("express");
const bcrypt = require("bcrypt");
const sql = require("mssql");
require("dotenv").config();
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

const dbConfig = process.env.SQLAZURECONNSTR_DefaultConnection;


sql.connect(dbConfig)
  .then(() => console.log("✅ Azure SQL Connected"))
  .catch(err => console.error("❌ DB Error:", err));

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/home.html");
});
/* -------- SIGNUP -------- */
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    await sql.connect(dbConfig);

    const check = await sql.query`
      SELECT id FROM users WHERE email=${email}
    `;

    if (check.recordset.length > 0) {
      return res.send("User already exists");
    }

    const hash = await bcrypt.hash(password, 10);

    await sql.query`
      INSERT INTO users (name, email, password)
      VALUES (${name}, ${email}, ${hash})
    `;

    res.redirect("/login.html");

  } catch (err) {
    res.status(500).send(err.message);
  }
});

/* -------- LOGIN -------- */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    await sql.connect(dbConfig);

    const result = await sql.query`
      SELECT * FROM users WHERE email=${email}
    `;

    if (result.recordset.length === 0) {
      return res.send("Invalid credentials");
    }

    const user = result.recordset[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.send("Invalid credentials");
    }

    res.redirect(`/profile.html?name=${user.name}&email=${user.email}`);

  } catch (err) {
    res.status(500).send(err.message);
  }
});

/* -------- SERVER -------- */
app.listen(process.env.PORT || 3000, () => {
  console.log("Server running");
});
