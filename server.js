const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const app = express();
const port = 3000;

// Инициализация и настройка базы данных SQLite
const db = new sqlite3.Database('users.db');
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
  db.run("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ["admin", bcrypt.hashSync("adminpassword", 10)]);
});

// Настройка Passport.js
passport.use(new LocalStrategy((username, password, done) => {
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
    if (err) {
      return done(err);
    }
    if (!row) {
      return done(null, false, { message: 'Incorrect username.' });
    }
    if (!bcrypt.compareSync(password, row.password)) {
      return done(null, false, { message: 'Incorrect password.' });
    }
    return done(null, row);
  });
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  db.get("SELECT * FROM users WHERE id = ?", [id], (err, row) => {
    done(err, row);
  });
});

// Настройка Express.js
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'your-secret-key', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

// Роуты
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

app.get('/profile', isAuthenticated, (req, res) => {
  res.send(`Welcome, ${req.user.username}! <a href="/logout">Logout</a>`);
});

app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/login.html');
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/profile',
  failureRedirect: '/login'
}));

app.get('/register', (req, res) => {
  res.sendFile(__dirname + '/register.html');
});

app.post('/register', (req, res) => {
  const username = req.body.username;
  const password = bcrypt.hashSync(req.body.password, 10);
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, password], (err) => {
    if (err) {
      return res.redirect('/register');
    }
    res.redirect('/login');
  });
});

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

// Middleware для проверки аутентификации
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

// Запуск сервера
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
