// app.js - SECURE VERSION

const express = require("express");
const session = require("express-session");
const SQLite = require("better-sqlite3");
const path = require("path");
const bcrypt = require("bcrypt");
const methodOverride = require("method-override");
const morgan = require("morgan");

const app = express();
const db = new SQLite("secure_tasks.db");

// ============================
// DATABASE INITIAL SETUP
// ============================

db.prepare(
  `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
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

const appPort = 3001;

// ============================
// EXPRESS SETUP
// ============================

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(methodOverride("_method"));
app.use(morgan("dev"));

// Secure session configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false, // Only set to true if running behind HTTPS
    },
  })
);

// Basic security headers
app.use((req, res, next) => {
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

// ============================
// HELPERS
// ============================

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

// ============================
// ROUTES
// ============================

// Redirect home → tasks
app.get("/", (req, res) => {
  res.redirect("/tasks");
});

// ----------------------------
// REGISTER (GET + POST)
// ----------------------------

app.get("/register", (req, res) => {
  res.render("register", { user: currentUser(req), error: null });
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.prepare(
      "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)"
    ).run(name, email, hashedPassword, "user");

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

// ----------------------------
// LOGIN (GET + POST)
// ----------------------------

// THIS was missing in your file — now fixed:
app.get("/login", (req, res) => {
  res.render("login", { user: currentUser(req), error: null });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const stmt = db.prepare("SELECT * FROM users WHERE email = ?");
  const user = stmt.get(email);

  if (!user) {
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
    console.warn("LOGIN FAILURE: wrong password for", email);
    res.status(401).render("login", {
      user: currentUser(req),
      error: "Invalid email or password",
    });
  }
});

// ----------------------------
// LOGOUT
// ----------------------------

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

// ----------------------------
// TASKS (secured)
// ----------------------------

app.get("/tasks", requireLogin, (req, res) => {
  const user = currentUser(req);
  const q = req.query.q;

  let tasks;

  if (q) {
    // Secure, parameterised query
    const stmt = db.prepare(
      "SELECT * FROM tasks WHERE title LIKE ? AND user_id = ?"
    );
    tasks = stmt.all(`%${q}%`, user.id);
  } else {
    tasks = db.prepare("SELECT * FROM tasks WHERE user_id = ?").all(user.id);
  }

  // Reflection parameter (escaped in view)
  const x = req.query.x || "";

  res.render("tasks_index", {
    user,
    tasks,
    q,
    x,
  });
});

// New task
app.get("/tasks/new", requireLogin, (req, res) => {
  res.render("tasks_new", { user: currentUser(req), error: null });
});

// Create task (safe — XSS removed in views)
app.post("/tasks", requireLogin, (req, res) => {
  const user = currentUser(req);
  const { title, description } = req.body;

  db.prepare(
    "INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)"
  ).run(user.id, title, description);

  res.redirect("/tasks");
});

// ----------------------------
// START SERVER
// ----------------------------

app.listen(appPort, () => {
  console.log(`Secure app listening on http://localhost:${appPort}`);
});
