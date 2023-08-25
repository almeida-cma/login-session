const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();

// Configurar SQLite
const db_name = "sampleDB.sqlite";
const db = new sqlite3.Database(db_name, (err) => {
    if (err) {
        return console.error(err.message);
    }
    console.log("Successful connection to the database");
});

const sql_create = `CREATE TABLE IF NOT EXISTS Users (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);`;

db.run(sql_create, (err) => {
    if (err) {
        return console.error(err.message);
    }
    console.log("Successful creation of the 'Users' table");
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Middleware for sessions
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true
}));

// Static files
app.use(express.static('public'));

app.post("/register", (req, res) => {
    const { username, password } = req.body;

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            return res.status(500).json({ error: err });
        } 

        const sql_insert = `INSERT INTO Users (username, password) VALUES (?, ?)`;
        db.run(sql_insert, [username, hash], (err) => {
            if (err) {
                return res.status(400).json({ error: err.message });
            }
            return res.status(201).json({ message: 'User created!' });
        });
    });
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;
    const sql_select = `SELECT * FROM Users WHERE username = ?`;

    db.get(sql_select, [username], (err, row) => {
        if (err) {
            return res.status(400).json({ error: err.message });
        }

        if (!row) {
            return res.status(400).json({ error: 'User not found. Please register!' });
        }

        bcrypt.compare(password, row.password, (err, result) => {
            if (err) {
                return res.status(400).json({ error: err.message });
            }

            if (result) {
                req.session.loggedin = true;
                req.session.username = username;
                return res.status(200).json({ message: 'Login successful!' });
            } else {
                return res.status(401).json({ message: 'Password is incorrect' });
            }
        });
    });
});

app.get('/dashboard', (req, res) => {
    if (req.session.loggedin) {
		// Middleware for sessions        res.send(`Welcome, ${req.session.username}! <a href='/logout'>Logout</a>`);
		res.sendFile(__dirname + '/public/dashboard.html');
    } else {
        res.send('Please login to view this page! <a href="/">Login</a>');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
