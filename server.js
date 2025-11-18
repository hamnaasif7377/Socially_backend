require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

// MySQL connection pool
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

// Test database connection
db.getConnection((err, connection) => {
    if (err) {
        console.error('Database connection failed:', err);
    } else {
        console.log('✓ Connected to MySQL database');
        connection.release();
    }
});

// ============================================
// ROUTES
// ============================================

// Root route
app.get("/", (req, res) => {
    res.send("Server is running!");
});

// ============================================
// USER AUTHENTICATION
// ============================================

// Login endpoint
app.post("/login", (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.json({ success: false, message: "Email and password required" });
    }

    db.query("SELECT * FROM test_users WHERE email = ?", [email], (err, results) => {
        if (err) {
            console.error('Login error:', err);
            return res.json({ success: false, message: "Database error" });
        }
        
        if (results.length === 0) {
            return res.json({ success: false, message: "User not found" });
        }

        const user = results[0];

    });
});

// Register endpoint
app.post("/register", async (req, res) => {
    const { uid, username, email, password } = req.body;
    
    if (!uid || !username || !email || !password) {
        return res.json({ success: false, message: "All fields required" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const username_lower = username.toLowerCase();

        db.query(
            "INSERT INTO users (uid, username, username_lower, email, password) VALUES (?, ?, ?, ?, ?)",
            [uid, username, username_lower, email, hashedPassword],
            (err) => {
                if (err) {
                    if (err.code === 'ER_DUP_ENTRY') {
                        return res.json({ success: false, message: "Username or email already exists" });
                    }
                    console.error('Registration error:', err);
                    return res.json({ success: false, message: "Registration failed" });
                }

                // Create user presence entry
                db.query(
                    "INSERT INTO user_presence (uid, status, lastSeen) VALUES (?, 'offline', ?)",
                    [uid, Date.now()],
                    (err) => {
                        if (err) console.error('Error creating user presence:', err);
                    }
                );

                res.json({ success: true, message: "Registration successful", uid });
            }
        );
    } catch (error) {
        console.error('Registration error:', error);
        res.json({ success: false, message: "Server error" });
    }
});

// ============================================
// USER OPERATIONS
// ============================================

// Get user by UID
app.get("/user/:uid", (req, res) => {
    const { uid } = req.params;

    db.query("SELECT * FROM users WHERE uid = ?", [uid], (err, results) => {
        if (err) return res.json({ success: false, message: err.message });
        if (results.length === 0) return res.json({ success: false, message: "User not found" });

        const user = results[0];
        delete user.password;

        res.json({ success: true, user });
    });
});

// Update user profile
app.put("/user/:uid", (req, res) => {
    const { uid } = req.params;
    const { name, lastname, bio, website, dob, profilePicture, profileImage } = req.body;

    db.query(
        `UPDATE users SET name = ?, lastname = ?, bio = ?, website = ?, dob = ?, 
         profilePicture = ?, profileImage = ? WHERE uid = ?`,
        [name, lastname, bio, website, dob, profilePicture, profileImage, uid],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, message: "Profile updated successfully" });
        }
    );
});

// ============================================
// POSTS
// ============================================

// Create post
app.post("/posts", (req, res) => {
    const { postId, userId, caption, location, imageUrls, timestamp } = req.body;

    db.query(
        "INSERT INTO posts (postId, userId, caption, location, timestamp) VALUES (?, ?, ?, ?, ?)",
        [postId, userId, caption, location, timestamp],
        (err) => {
            if (err) return res.json({ success: false, message: err.message });

            // Insert images if any
            if (imageUrls && imageUrls.length > 0) {
                const imageValues = imageUrls.map((url, index) => [postId, url, index]);
                db.query(
                    "INSERT INTO post_images (postId, imageUrl, orderIndex) VALUES ?",
                    [imageValues],
                    (err) => {
                        if (err) console.error('Error inserting images:', err);
                    }
                );
            }

            // Update user post count
            db.query("UPDATE users SET postCount = postCount + 1 WHERE uid = ?", [userId]);

            res.json({ success: true, message: "Post created successfully" });
        }
    );
});

// Get posts by user
app.get("/posts/:userId", (req, res) => {
    const { userId } = req.params;

    db.query(
        `SELECT p.*, GROUP_CONCAT(pi.imageUrl ORDER BY pi.orderIndex) as imageUrls
         FROM posts p
         LEFT JOIN post_images pi ON p.postId = pi.postId
         WHERE p.userId = ?
         GROUP BY p.postId
         ORDER BY p.timestamp DESC`,
        [userId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });

            const posts = results.map(post => ({
                ...post,
                imageUrls: post.imageUrls ? post.imageUrls.split(',') : []
            }));

            res.json({ success: true, posts });
        }
    );
});

// ============================================
// MESSAGES
// ============================================

// Send message
app.post("/messages", (req, res) => {
    const { messageId, senderId, receiverId, messageText, timestamp } = req.body;

    db.query(
        "INSERT INTO messages (messageId, senderId, receiverId, messageText, timestamp) VALUES (?, ?, ?, ?, ?)",
        [messageId, senderId, receiverId, messageText, timestamp],
        (err) => {
            if (err) return res.json({ success: false, message: err.message });

            // Update conversation
            db.query(
                `INSERT INTO conversations (user1_uid, user2_uid, lastMessage, timestamp) 
                 VALUES (?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE lastMessage = ?, timestamp = ?`,
                [senderId, receiverId, messageText, timestamp, messageText, timestamp]
            );

            res.json({ success: true, message: "Message sent successfully" });
        }
    );
});

// Get messages between two users
app.get("/messages/:user1/:user2", (req, res) => {
    const { user1, user2 } = req.params;

    db.query(
        `SELECT * FROM messages 
         WHERE (senderId = ? AND receiverId = ?) OR (senderId = ? AND receiverId = ?)
         ORDER BY timestamp ASC`,
        [user1, user2, user2, user1],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, messages: results });
        }
    );
});

// ============================================
// FOLLOWERS
// ============================================

// Follow user
app.post("/follow", (req, res) => {
    const { follower_uid, following_uid } = req.body;

    db.query(
        "INSERT INTO user_followers (follower_uid, following_uid, status) VALUES (?, ?, 'accepted')",
        [follower_uid, following_uid],
        (err) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.json({ success: false, message: "Already following" });
                }
                return res.json({ success: false, message: err.message });
            }

            // Update counts
            db.query("UPDATE users SET followingCount = followingCount + 1 WHERE uid = ?", [follower_uid]);
            db.query("UPDATE users SET followersCount = followersCount + 1 WHERE uid = ?", [following_uid]);

            res.json({ success: true, message: "Followed successfully" });
        }
    );
});

// Unfollow user
app.delete("/follow/:follower_uid/:following_uid", (req, res) => {
    const { follower_uid, following_uid } = req.params;

    db.query(
        "DELETE FROM user_followers WHERE follower_uid = ? AND following_uid = ?",
        [follower_uid, following_uid],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });

            if (results.affectedRows > 0) {
                // Update counts
                db.query("UPDATE users SET followingCount = followingCount - 1 WHERE uid = ?", [follower_uid]);
                db.query("UPDATE users SET followersCount = followersCount - 1 WHERE uid = ?", [following_uid]);

                res.json({ success: true, message: "Unfollowed successfully" });
            } else {
                res.json({ success: false, message: "Not following" });
            }
        }
    );
});

// ============================================
// START SERVER
// ============================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✓ Server running on port ${PORT}`);
});

module.exports = { db };