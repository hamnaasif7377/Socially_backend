// server.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
const session = require('express-session');

// ---- SESSION MANAGEMENT ----
app.use(
    session({
        secret: "supersecretkey123",
        resave: false,
        saveUninitialized: true,
        cookie: {
            maxAge: 30 * 24 * 60 * 60 * 1000
        }
    })
);

// ======================================================
// 🔥 FIXED DATABASE CONNECTION (POOL + SSL FOR RAILWAY)
// ======================================================
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    ssl: { rejectUnauthorized: false } // <-- RAILWAY REQUIRES SSL
});

// Test pool connection
db.getConnection((err, connection) => {
    if (err) {
        console.error("❌ Database connection failed:", err);
    } else {
        console.log("✅ Database connected!");
        connection.release();
    }
});

// ---- GLOBAL UID COUNTER ----
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

            if (results.length > 0) {
                return res.json({ success: false, message: "User already exists" });
            }

            const uid = nextUid++;

            db.query(
                `INSERT INTO users
                (uid, username, username_lower, name, lastname, email, password, dob, profileImage, followersCount, followingCount, postCount, bio, website, profilePicture)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, '', '', '')`,
                [uid, username, username.toLowerCase(), name, lastname, email, password, dob, profileImage],
                (err) => {
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
        if (err) {
            console.error('Login error:', err);
            return res.json({ success: false, message: "Database error" });
        }

        if (results.length === 0) {
            return res.json({ success: false, message: "User not found" });
        }

        const user = results[0];
        const userPassword = user.password ? String(user.password) : "";

        if (password === userPassword) {
            const { password, ...userData } = user;
            return res.json({ success: true, message: "Login successful", user: userData });
        } else {
            return res.json({ success: false, message: "Invalid password" });
        }
    });
});

// ---- SESSION CHECK ----
app.get("/session", (req, res) => {
    if (!req.session.userId) return res.json({ loggedIn: false });

    db.query("SELECT * FROM users WHERE uid = ?", [req.session.userId], (err, results) => {
        if (err || results.length === 0) return res.json({ loggedIn: false });

        const user = results[0];
        delete user.password;

        res.json({ loggedIn: true, user });
    });
});

// ---- LOGOUT ----
app.post("/logout", (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true, message: "Logged out" });
    });
});

// ---------- STORY ROUTES (UNCHANGED) ----------
app.post("/stories/upload", (req, res) => {
    const { storyId, userId, userName, userProfileImage, imageBase64, viewType, timestamp, expiryTime } = req.body;

    if (!storyId || !userId || !imageBase64) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    db.query(
        `INSERT INTO stories (storyId, userId, userName, userProfileImage, imageBase64, viewType, timestamp, expiryTime)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [storyId, userId, userName, userProfileImage, imageBase64, viewType, timestamp, expiryTime],
        (err) => {
            if (err) {
                console.error("Story upload error:", err);
                return res.json({ success: false, message: err.message });
            }
            res.json({ success: true, message: "Story uploaded successfully", storyId });
        }
    );
});

app.get("/stories/user/:userId", (req, res) => {
    const { userId } = req.params;
    const currentTime = Date.now();

    db.query(
        `SELECT * FROM stories WHERE userId = ? AND expiryTime > ? ORDER BY timestamp ASC`,
        [userId, currentTime],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, stories: results });
        }
    );
});

app.get("/stories/all", (req, res) => {
    const currentTime = Date.now();

    db.query(
        `SELECT s.*, u.profileImage 
         FROM stories s
         LEFT JOIN users u ON s.userId = u.uid
         WHERE s.expiryTime > ?
         ORDER BY s.timestamp DESC`,
        [currentTime],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });

            const storiesByUser = {};
            results.forEach(story => {
                if (!storiesByUser[story.userId]) {
                    storiesByUser[story.userId] = {
                        userId: story.userId,
                        username: story.userName || story.username,
                        profileImage: story.profileImage || story.userProfileImage,
                        stories: []
                    };
                }
                storiesByUser[story.userId].stories.push({
                    storyId: story.storyId,
                    userId: story.userId,
                    userName: story.userName || story.username,
                    userProfileImage: story.userProfileImage || story.profileImage,
                    imageBase64: story.imageBase64,
                    viewType: story.viewType,
                    timestamp: story.timestamp,
                    expiryTime: story.expiryTime
                });
            });

            res.json({ success: true, users: Object.values(storiesByUser) });
        }
    );
});

app.delete("/stories/cleanup", (req, res) => {
    const currentTime = Date.now();

    db.query("DELETE FROM stories WHERE expiryTime < ?", [currentTime], (err, result) => {
        if (err) return res.json({ success: false, message: err.message });

        res.json({
            success: true,
            message: `Deleted ${result.affectedRows} expired stories`
        });
    });
});

app.get("/users/:userId", (req, res) => {
    const { userId } = req.params;

    db.query(
        "SELECT uid, username, email, name, profileImage FROM users WHERE uid = ?",
        [userId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });
            if (results.length === 0) return res.json({ success: false, message: "User not found" });

            res.json({ success: true, user: results[0] });
        }
    );
});

// GLOBAL ERROR HANDLING
process.on('uncaughtException', err => console.error('Uncaught Exception:', err));
process.on('unhandledRejection', err => console.error('Unhandled Rejection:', err));

app.listen(process.env.PORT || 3000, () => {
    console.log("Server running on port " + (process.env.PORT || 3000));
});
