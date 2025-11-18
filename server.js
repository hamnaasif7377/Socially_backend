require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

// ============================================
// MYSQL CONNECTION
// ============================================

const db = mysql.createPool({
    host: process.env.MYSQLHOST,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE,
    port: process.env.MYSQLPORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// DB Connection Test
db.getConnection((err, conn) => {
    if (err) {
        console.error("Database connection failed:", err);
    } else {
        console.log("✓ Connected to MySQL");
        conn.release();
        createTables(); // important!
    }
});

// ============================================
// CREATE TABLES (RUNS AUTOMATICALLY)
// ============================================

function createTables() {
    console.log("✓ Creating tables if not exist...");

    db.query(`
        CREATE TABLE IF NOT EXISTS users (
            uid VARCHAR(255) PRIMARY KEY,
            username VARCHAR(100),
            username_lower VARCHAR(100),
            name VARCHAR(100),
            lastname VARCHAR(100),
            bio TEXT,
            website VARCHAR(255),
            email VARCHAR(255) UNIQUE,
            dob VARCHAR(50),
            profilePicture TEXT,
            profileImage TEXT,
            followersCount INT DEFAULT 0,
            followingCount INT DEFAULT 0,
            postCount INT DEFAULT 0,
            password TEXT
        )
    `);

    db.query(`
        CREATE TABLE IF NOT EXISTS user_followers (
            follower_uid VARCHAR(255),
            following_uid VARCHAR(255),
            status ENUM('accepted', 'pending') DEFAULT 'accepted',
            PRIMARY KEY (follower_uid, following_uid)
        )
    `);

    db.query(`
        CREATE TABLE IF NOT EXISTS user_presence (
            uid VARCHAR(255) PRIMARY KEY,
            status VARCHAR(10),
            lastSeen BIGINT
        )
    `);

    db.query(`
        CREATE TABLE IF NOT EXISTS posts (
            postId VARCHAR(255) PRIMARY KEY,
            userId VARCHAR(255),
            caption TEXT,
            location VARCHAR(255),
            timestamp BIGINT
        )
    `);

    db.query(`
        CREATE TABLE IF NOT EXISTS post_images (
            id INT AUTO_INCREMENT PRIMARY KEY,
            postId VARCHAR(255),
            imageUrl TEXT,
            orderIndex INT
        )
    `);

    db.query(`
        CREATE TABLE IF NOT EXISTS messages (
            messageId VARCHAR(255) PRIMARY KEY,
            senderId VARCHAR(255),
            receiverId VARCHAR(255),
            messageText TEXT,
            timestamp BIGINT
        )
    `);

    db.query(`
        CREATE TABLE IF NOT EXISTS conversations (
            user1_uid VARCHAR(255),
            user2_uid VARCHAR(255),
            lastMessage TEXT,
            timestamp BIGINT,
            PRIMARY KEY (user1_uid, user2_uid)
        )
    `);

    console.log("✓ All tables ready!");
}

// ============================================
// ROUTES
// ============================================

// Root
app.get("/", (req, res) => {
    res.send("Server is running!");
});

// ============================================
// LOGIN
// ============================================

app.post("/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password)
        return res.json({ success: false, message: "Email and password required" });

    db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
        if (err) return res.json({ success: false, message: "DB error" });

        if (results.length === 0)
            return res.json({ success: false, message: "User not found" });

        const user = results[0];

        if (!bcrypt.compareSync(password, user.password))
            return res.json({ success: false, message: "Invalid password" });

        delete user.password;

        db.query(`
            SELECT 
                (SELECT JSON_OBJECTAGG(follower_uid, TRUE) FROM user_followers 
                 WHERE following_uid = ? AND status='accepted') AS followers,
                (SELECT JSON_OBJECTAGG(following_uid, TRUE) FROM user_followers 
                 WHERE follower_uid = ? AND status='accepted') AS following,
                (SELECT JSON_OBJECTAGG(follower_uid, TRUE) FROM user_followers 
                 WHERE following_uid = ? AND status='pending') AS receivedRequests,
                (SELECT JSON_OBJECTAGG(following_uid, TRUE) FROM user_followers 
                 WHERE follower_uid = ? AND status='pending') AS sentRequests
        `, [user.uid, user.uid, user.uid, user.uid], (err, rel) => {
            if (!err && rel.length > 0) {
                user.followers = rel[0].followers || {};
                user.following = rel[0].following || {};
                user.receivedRequests = rel[0].receivedRequests || {};
                user.sentRequests = rel[0].sentRequests || {};
            }

            res.json({ success: true, message: "Login successful", user });
        });

    });
});

// ============================================
// REGISTER
// ============================================

app.post("/register", async (req, res) => {
    const { uid, username, email, password } = req.body;

    if (!uid || !username || !email || !password)
        return res.json({ success: false, message: "All fields required" });

    const hashed = await bcrypt.hash(password, 10);

    db.query(
        "INSERT INTO users (uid, username, username_lower, email, password) VALUES (?, ?, ?, ?, ?)",
        [uid, username, username.toLowerCase(), email, hashed],
        (err) => {
            if (err) {
                if (err.code === "ER_DUP_ENTRY")
                    return res.json({ success: false, message: "User already exists" });

                return res.json({ success: false, message: "DB error" });
            }

            db.query(
                "INSERT INTO user_presence (uid, status, lastSeen) VALUES (?, 'offline', ?)",
                [uid, Date.now()]
            );

            res.json({ success: true, message: "Registration successful", uid });
        }
    );
});

// ============================================
// GET USER
// ============================================

app.get("/user/:uid", (req, res) => {
    db.query("SELECT * FROM users WHERE uid = ?", [req.params.uid], (err, results) => {
        if (err) return res.json({ success: false, message: "DB error" });
        if (results.length === 0) return res.json({ success: false, message: "Not found" });

        const user = results[0];
        delete user.password;

        res.json({ success: true, user });
    });
});

// ============================================
// FOLLOW / UNFOLLOW
// ============================================

app.post("/follow", (req, res) => {
    const { follower_uid, following_uid } = req.body;

    db.query(
        "INSERT INTO user_followers (follower_uid, following_uid, status) VALUES (?, ?, 'accepted')",
        [follower_uid, following_uid],
        (err) => {
            if (err) return res.json({ success: false, message: "Already following" });

            db.query("UPDATE users SET followingCount = followingCount + 1 WHERE uid = ?", [follower_uid]);
            db.query("UPDATE users SET followersCount = followersCount + 1 WHERE uid = ?", [following_uid]);

            res.json({ success: true });
        }
    );
});

app.delete("/follow/:follower/:following", (req, res) => {
    const { follower, following } = req.params;

    db.query("DELETE FROM user_followers WHERE follower_uid = ? AND following_uid = ?", [follower, following], (err, result) => {
        if (err) return res.json({ success: false });

        if (result.affectedRows > 0) {
            db.query("UPDATE users SET followingCount = followingCount - 1 WHERE uid = ?", [follower]);
            db.query("UPDATE users SET followersCount = followersCount - 1 WHERE uid = ?", [following]);
        }

        res.json({ success: true });
    });
});

// ============================================
// START SERVER
// ============================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✓ Server running on port ${PORT}`);
});

module.exports = { db };
