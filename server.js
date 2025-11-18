// server.js
require('dotenv').config(); // Load .env variables
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());

// MySQL connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,   // Railway DB host
    user: process.env.DB_USER,   // Railway DB user
    password: process.env.DB_PASS, // Railway DB password
    database: process.env.DB_NAME, // Railway DB name
    port: process.env.DB_PORT     // Railway DB port (3306)
});

db.connect(err => {
    if (err) {
        console.error('Database connection failed:', err);
    } else {
        console.log('Database connected!');
    }
});

// Simple login route
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({ success: false, message: "Email and password required" });
    }

    db.query("SELECT * FROM test_users WHERE email = ?", [email], (err, results) => {
        if (err) {
            console.error('Login SQL error:', err);
            return res.json({ success: false, message: "Database error" });
        }

        if (results.length === 0) {
            return res.json({ success: false, message: "User not found" });
        }

        const user = results[0]; 

        // Compare password
        // Compare password (plain text for testing only)
if (password === user.password) {
    const { password, ...userData } = user;
    return res.json({ success: true, message: "Login successful", user: userData });
} else {
    return res.json({ success: false, message: "Invalid password" });
}

    });
});

// Temporary UID counter
let nextUid = 1; // start from 1 or load from DB if you want

app.post("/register", (req, res) => {
    const { username, name, lastname, email, password, dob, profileImage } = req.body;

    if (!username || !name || !lastname || !email || !password) {
        return res.json({ success: false, message: "Required fields missing" });
    }

    // Check if user exists
    db.query(
        "SELECT * FROM users WHERE email = ? OR username = ?",
        [email, username],
        (err, results) => {
            if (err) return res.json({ success: false, message: "Database error" });
            if (results.length > 0) return res.json({ success: false, message: "User exists" });

            // Assign UID and increment
            const uid = nextUid;
            nextUid++;

            db.query(
                `INSERT INTO users (uid, username, username_lower, name, lastname, email, password, dob, profileImage, followersCount, followingCount, postCount, bio, website, profilePicture) 
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



// Use PORT from Railway or default 8080
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));







