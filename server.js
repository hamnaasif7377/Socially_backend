// server.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');

const app = express();
app.use(express.json());

// ---- DATABASE CONNECTION ----
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
});

db.connect(err => {
    if (err) {
        console.error('Database connection failed:', err);
    } else {
        console.log('Database connected!');
    }
});

// ---- GLOBAL UID COUNTER (simulating AUTO_INCREMENT) ----
let nextUid = 1;

// ---- REGISTER ROUTE ----
app.post("/register", (req, res) => {
    const { username, name, lastname, email, password, dob, profileImage } = req.body;

    if (!username || !name || !lastname || !email || !password) {
        return res.json({ success: false, message: "Required fields missing" });
    }

    db.query(
        "SELECT * FROM users WHERE email = ? OR username = ?",
        [email, username],
        (err, results) => {
            if (err) return res.json({ success: false, message: "Database error" });
            if (results.length > 0) return res.json({ success: false, message: "User already exists" });

            const uid = nextUid++;
            db.query(
                `INSERT INTO users
                (uid, username, username_lower, name, lastname, email, password, dob, profileImage, followersCount, followingCount, postCount, bio, website, profilePicture)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, '', '', '')`,
                [uid, username, username.toLowerCase(), name, lastname, email, password, dob, profileImage],
                (err, result) => {
                    if (err) return res.json({ success: false, message: "Database error" });
                    res.json({ success: true, message: "Registration successful", userId: uid });
                }
            );
        }
    );
});

// ---- LOGIN ROUTE ----
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({ success: false, message: "Email and password required" });
    }

    db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
        if (err) return res.json({ success: false, message: "Database error" });
        if (results.length === 0) return res.json({ success: false, message: "User not found" });

        const user = results[0];

        if (password === user.password) {
            const { password, ...userData } = user;
            res.json({ success: true, message: "Login successful", user: userData });
        } else {
            res.json({ success: false, message: "Invalid password" });
        }
    });
});

// ---- GLOBAL ERROR HANDLING ----
process.on('uncaughtException', err => console.error('Uncaught Exception:', err));
process.on('unhandledRejection', err => console.error('Unhandled Rejection:', err));

// ---- START SERVER ----
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log('Ready to accept requests...');
});
