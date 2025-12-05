// app.js - INSECURE VERSION (for insecure branch)

const express = require("express");
const session = require("express-session");
const SQLite = require("better-sqlite3");
const path = require("path");
const bcrypt = require("bcrypt"); // will use properly in secure version
const methodOverride = require("method-override");
const morgan = require("morgan");

const app = express();
const db = new SQLite("secure_tasks.db");

// Basic DB setup (users + tasks) - for demo only
db.prepare(
  `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,        -- INSECURE: plain text password
    role TEXT DEFAULT 'user'
  )
`
).run();

db.prepare(
  `
  CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`
).run();

const appPort = 3000;

// Middlewares
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(methodOverride("_method"));
app.use(morgan("dev"));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false, // set to true if you deploy behind HTTPS
    },
  })
);

app.use((req, res, next) => {
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

// Helpers
function currentUser(req) {
  if (!req.session.userId) return null;
  const stmt = db.prepare("SELECT * FROM users WHERE id = ?");
  return stmt.get(req.session.userId);
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/login");
  }
  next();
}

// ===== Routes =====

// Home -> tasks
app.get("/", (req, res) => {
  res.redirect("/tasks");
});

// Register (secure password storage)
app.get("/register", (req, res) => {
  res.render("register", { user: currentUser(req), error: null });
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // SECURE: hash password before storing
    const hashedPassword = await bcrypt.hash(password, 10);

    const stmt = db.prepare(
      "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)"
    );
    stmt.run(name, email, hashedPassword, "user");

    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    req.session.userId = user.id;
    res.redirect("/tasks");
  } catch (err) {
    console.error("Register error:", err);
    res.render("register", {
      user: currentUser(req),
      error: "Email already used or error",
    });
  }
});

// Login (secure check + logging)
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const stmt = db.prepare("SELECT * FROM users WHERE email = ?");
  const user = stmt.get(email);

  if (!user) {
    // Optional: security logging but DO NOT log password
    console.warn("LOGIN FAILURE: unknown email", email);
    return res.status(401).render("login", {
      user: currentUser(req),
      error: "Invalid email or password",
    });
  }

  const ok = await bcrypt.compare(password, user.password);

  if (ok) {
    console.info("LOGIN SUCCESS:", email);
    req.session.userId = user.id;
    res.redirect("/tasks");
  } else {
    console.warn("LOGIN FAILURE: bad password for", email);
    res.status(401).render("login", {
      user: currentUser(req),
      error: "Invalid email or password",
    });
  }
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

// Tasks list + secure search + reflected XSS + DOM XSS
app.get("/tasks", requireLogin, (req, res) => {
  const user = currentUser(req);

  let tasks;
  const q = req.query.q;

  if (q) {
    // SECURE: parameterised query, prevents SQL injection
    const stmt = db.prepare(
      "SELECT * FROM tasks WHERE title LIKE ? AND user_id = ?"
    );
    tasks = stmt.all(`%${q}%`, user.id);
  } else {
    const stmt = db.prepare("SELECT * FROM tasks WHERE user_id = ?");
    tasks = stmt.all(user.id);
  }

  const x = req.query.x || ""; // used for reflected XSS

  res.render("tasks_index", {
    user,
    tasks,
    q,
    x, // used in the view
  });
});

// New task form
app.get("/tasks/new", requireLogin, (req, res) => {
  res.render("tasks_new", { user: currentUser(req), error: null });
});

// Create task (stored XSS in description)
app.post("/tasks", requireLogin, (req, res) => {
  const user = currentUser(req);
  const { title, description } = req.body;

  const stmt = db.prepare(
    "INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)"
  );
  stmt.run(user.id, title, description);

  res.redirect("/tasks");
});

// (optional) simple show / delete left out for brevity; list + create is enough for demo

app.listen(appPort, () => {
  console.log(`Insecure app listening on http://localhost:${appPort}`);
});
