// server.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const app = express();
app.use(express.json({ limit: '50mb' })); // Increased limit for Base64 images
app.use(express.urlencoded({ limit: '50mb', extended: true }));

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
        
        // Create stories table if it doesn't exist
        db.query(`
            CREATE TABLE IF NOT EXISTS stories (
                id INT AUTO_INCREMENT PRIMARY KEY,
                storyId VARCHAR(255) UNIQUE,
                userId VARCHAR(255),
                userName VARCHAR(255),
                userProfileImage LONGTEXT,
                imageBase64 LONGTEXT,
                viewType VARCHAR(50),
                timestamp BIGINT,
                expiryTime BIGINT,
                INDEX idx_userId (userId),
                INDEX idx_expiryTime (expiryTime)
            )
        `, (err) => {
            if (err) {
                console.error("Error creating stories table:", err);
            } else {
                console.log("Stories table ready.");
            }
        });
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
        if (err) {
            console.error('Login error:', err);
            return res.json({ success: false, message: "Database error" });
        }
        if (results.length === 0) {
            return res.json({ success: false, message: "User not found" });
        }
        const user = results[0];
        // Convert password to string in case it's not
        const userPassword = user.password ? String(user.password) : "";
        if (password === userPassword) {
            const { password, ...userData } = user; // remove password from response
            return res.json({ success: true, message: "Login successful", user: userData });
        } else {
            return res.json({ success: false, message: "Invalid password" });
        }
    });
});

// ============================================
// STORY ENDPOINTS (NEW - ADDED BELOW)
// ============================================

// ---- UPLOAD STORY ENDPOINT ----
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
            res.json({ 
                success: true, 
                message: "Story uploaded successfully",
                storyId: storyId
            });
        }
    );
});

// ---- GET USER STORIES ENDPOINT ----
app.get("/stories/user/:userId", (req, res) => {
    const { userId } = req.params;
    const currentTime = Date.now();
    
    db.query(
        `SELECT * FROM stories 
         WHERE userId = ? AND expiryTime > ?
         ORDER BY timestamp ASC`,
        [userId, currentTime],
        (err, results) => {
            if (err) {
                return res.json({ success: false, message: err.message });
            }
            res.json({ success: true, stories: results });
        }
    );
});

// ---- GET ALL ACTIVE STORIES ENDPOINT ----
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
            if (err) {
                return res.json({ success: false, message: err.message });
            }
            
            // Group stories by user
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

// ---- DELETE EXPIRED STORIES (cleanup) ----
app.delete("/stories/cleanup", (req, res) => {
    const currentTime = Date.now();
    
    db.query(
        "DELETE FROM stories WHERE expiryTime < ?",
        [currentTime],
        (err, result) => {
            if (err) {
                return res.json({ success: false, message: err.message });
            }
            res.json({ 
                success: true, 
                message: `Deleted ${result.affectedRows} expired stories` 
            });
        }
    );
});

// ---- GET USER PROFILE ----
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

// ---- GLOBAL ERROR HANDLING ----
process.on('uncaughtException', err => console.error('Uncaught Exception:', err));
process.on('unhandledRejection', err => console.error('Unhandled Rejection:', err));

// ---- START SERVER ----
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log('Ready to accept requests...');
});