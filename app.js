const express = require("express");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const path = require("path");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());

const dbPath = path.join(__dirname, "userData.db");
let db = null;

const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(3000, () => {
      console.log("Server running at http://localhost:3000/");
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};

initializeDbAndServer();


// API 1 - Register User
app.post("/register", async (request, response) => {
  const { username, name, password, gender, location } = request.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const userCheckQuery = `SELECT * FROM user WHERE username = ?;`;
  const dbUser = await db.get(userCheckQuery, [username]);

  if (dbUser) {
    response.status(400);
    response.send("User already exists");
  } else if (password.length < 5) {
    response.status(400);
    response.send("Password is too short");
  } else {
    const insertUserQuery = `
      INSERT INTO user (username, name, password, gender, location)
      VALUES (?, ?, ?, ?, ?);`;
    await db.run(insertUserQuery, [username, name, hashedPassword, gender, location]);
    response.status(200);
    response.send("User created successfully");
  }
});


// API 2 - Login User
app.post("/login", async (request, response) => {
  const { username, password } = request.body;

  const userCheckQuery = `SELECT * FROM user WHERE username = ?;`;
  const dbUser = await db.get(userCheckQuery, [username]);

  if (!dbUser) {
    response.status(400);
    response.send("Invalid user");
  } else {
    const isPasswordMatch = await bcrypt.compare(password, dbUser.password);
    if (!isPasswordMatch) {
      response.status(400);
      response.send("Invalid password");
    } else {
      response.status(200);
      response.send("Login success!");
    }
  }
});


// API 3 - Change Password
app.put("/change-password", async (request, response) => {
  const { username, oldPassword, newPassword } = request.body;

  const userCheckQuery = `SELECT * FROM user WHERE username = ?;`;
  const dbUser = await db.get(userCheckQuery, [username]);

  if (!dbUser) {
    response.status(400);
    response.send("Invalid user");
  } else {
    const isPasswordMatch = await bcrypt.compare(oldPassword, dbUser.password);

    if (!isPasswordMatch) {
      response.status(400);
      response.send("Invalid current password");
    } else if (newPassword.length < 5) {
      response.status(400);
      response.send("Password is too short");
    } else {
      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      const updatePasswordQuery = `
        UPDATE user SET password = ? WHERE username = ?;`;
      await db.run(updatePasswordQuery, [hashedNewPassword, username]);

      response.status(200);
      response.send("Password updated");
    }
  }
});

module.exports = app;   // ✅ Export express instance
