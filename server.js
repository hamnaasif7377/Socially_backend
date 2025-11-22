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
    ssl: { rejectUnauthorized: false }
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

// ======================================================
// CREATE ALL TABLES ON STARTUP
// ======================================================

// Create users table with all required columns
const createUsersTable = `
CREATE TABLE IF NOT EXISTS users (
    uid VARCHAR(255) PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    username_lower VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    lastname VARCHAR(255),
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    dob VARCHAR(50),
    profileImage LONGTEXT,
    profilePicture LONGTEXT,
    bio TEXT,
    website VARCHAR(255),
    followersCount INT DEFAULT 0,
    followingCount INT DEFAULT 0,
    postCount INT DEFAULT 0,
    fcmToken TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username_lower (username_lower),
    INDEX idx_email (email)
)`;

db.query(createUsersTable, (err) => {
    if (err) console.error("Error creating users table:", err);
    else console.log("✅ Users table ready");
});

// Create posts table
const createPostsTable = `
CREATE TABLE IF NOT EXISTS posts (
    postId VARCHAR(255) PRIMARY KEY,
    userId VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    profileImage TEXT,
    images JSON,
    caption TEXT,
    location VARCHAR(255),
    timestamp BIGINT NOT NULL,
    likesCount INT DEFAULT 0,
    commentsCount INT DEFAULT 0,
    INDEX idx_user (userId),
    INDEX idx_timestamp (timestamp DESC)
)`;

db.query(createPostsTable, (err) => {
    if (err) console.error("Error creating posts table:", err);
    else console.log("✅ Posts table ready");
});

// Create stories table
const createStoriesTable = `
CREATE TABLE IF NOT EXISTS stories (
    storyId VARCHAR(255) PRIMARY KEY,
    userId VARCHAR(255) NOT NULL,
    userName VARCHAR(255),
    username VARCHAR(255),
    userProfileImage LONGTEXT,
    profileImage LONGTEXT,
    imageBase64 LONGTEXT NOT NULL,
    viewType VARCHAR(50),
    timestamp BIGINT NOT NULL,
    expiryTime BIGINT NOT NULL,
    INDEX idx_user (userId),
    INDEX idx_expiry (expiryTime)
)`;

db.query(createStoriesTable, (err) => {
    if (err) console.error("Error creating stories table:", err);
    else console.log("✅ Stories table ready");
});

// Create followers table
const createFollowersTable = `
CREATE TABLE IF NOT EXISTS followers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userId VARCHAR(255) NOT NULL,
    followerId VARCHAR(255) NOT NULL,
    timestamp BIGINT NOT NULL,
    UNIQUE KEY unique_follow (userId, followerId),
    INDEX idx_user (userId),
    INDEX idx_follower (followerId)
)`;

db.query(createFollowersTable, (err) => {
    if (err) console.error("Error creating followers table:", err);
    else console.log("✅ Followers table ready");
});

// Create follow requests table
const createFollowRequestsTable = `
CREATE TABLE IF NOT EXISTS follow_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    senderId VARCHAR(255) NOT NULL,
    receiverId VARCHAR(255) NOT NULL,
    timestamp BIGINT NOT NULL,
    status ENUM('pending', 'accepted', 'rejected') DEFAULT 'pending',
    UNIQUE KEY unique_request (senderId, receiverId),
    INDEX idx_sender (senderId),
    INDEX idx_receiver (receiverId),
    INDEX idx_status (status)
)`;

db.query(createFollowRequestsTable, (err) => {
    if (err) console.error("Error creating follow_requests table:", err);
    else console.log("✅ Follow requests table ready");
});

// ======================================================
// HELPER FUNCTIONS
// ======================================================

function generateUniqueUid() {
    return Date.now().toString() + Math.random().toString(36).substr(2, 9);
}

// ======================================================
// AUTHENTICATION ROUTES
// ======================================================

// ---- REGISTER ROUTE ----
app.post("/register", (req, res) => {
    const { username, name, lastname, email, password, dob, profileImage } = req.body;

    console.log("📝 Registration attempt:", { 
        username, 
        email, 
        name, 
        lastname,
        hasDob: !!dob,
        hasProfileImage: !!profileImage 
    });

    // Validate required fields
    if (!username || !name || !lastname || !email || !password) {
        console.log("❌ Missing required fields");
        return res.json({ 
            success: false, 
            message: "Required fields missing" 
        });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        console.log("❌ Invalid email format:", email);
        return res.json({ 
            success: false, 
            message: "Invalid email format" 
        });
    }

    // Validate username (alphanumeric, underscores, 3-30 chars)
    const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
    if (!usernameRegex.test(username)) {
        console.log("❌ Invalid username format:", username);
        return res.json({ 
            success: false, 
            message: "Username must be 3-30 characters (letters, numbers, underscores only)" 
        });
    }

    // Validate password length
    if (password.length < 6) {
        console.log("❌ Password too short");
        return res.json({ 
            success: false, 
            message: "Password must be at least 6 characters" 
        });
    }

    // Check if user already exists
    db.query(
        "SELECT * FROM users WHERE email = ? OR username = ?",
        [email, username],
        (err, results) => {
            if (err) {
                console.error("❌ Database error checking existing user:", err.message);
                return res.json({ 
                    success: false, 
                    message: "Database error: " + err.message 
                });
            }

            if (results.length > 0) {
                const existingUser = results[0];
                if (existingUser.email === email) {
                    console.log("❌ Email already registered:", email);
                    return res.json({ 
                        success: false, 
                        message: "Email already registered" 
                    });
                }
                if (existingUser.username === username) {
                    console.log("❌ Username already taken:", username);
                    return res.json({ 
                        success: false, 
                        message: "Username already taken" 
                    });
                }
            }

            // Generate unique UID
            const uid = generateUniqueUid();

            console.log("✅ Validation passed, inserting user:", uid);

            const insertQuery = `
                INSERT INTO users
                (uid, username, username_lower, name, lastname, email, password, dob, profileImage, 
                 profilePicture, bio, website, followersCount, followingCount, postCount, fcmToken)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', '', 0, 0, 0, '')`;

            const insertValues = [
                uid, 
                username, 
                username.toLowerCase(), 
                name, 
                lastname, 
                email, 
                password, 
                dob || '', 
                profileImage || ''
            ];

            db.query(insertQuery, insertValues, (err) => {
                if (err) {
                    console.error("❌ Database error inserting user:");
                    console.error("Error code:", err.code);
                    console.error("Error message:", err.message);
                    
                    return res.json({ 
                        success: false, 
                        message: "Registration failed: " + err.message 
                    });
                }

                console.log(`✅ User registered successfully: ${username} (UID: ${uid})`);

                // Return user data (excluding password)
                res.json({ 
                    success: true, 
                    message: "Registration successful",
                    user: {
                        uid: uid,
                        username: username,
                        username_lower: username.toLowerCase(),
                        name: name,
                        lastname: lastname,
                        email: email,
                        dob: dob || '',
                        profileImage: profileImage || '',
                        profilePicture: '',
                        bio: '',
                        website: '',
                        followersCount: 0,
                        followingCount: 0,
                        postCount: 0
                    }
                });
            });
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

// ======================================================
// USER ENDPOINTS
// ======================================================

app.get("/users/:userId", (req, res) => {
    const { userId } = req.params;

    db.query(
        "SELECT uid, username, username_lower, email, name, lastname, profileImage, profilePicture, bio, website, followersCount, followingCount, postCount FROM users WHERE uid = ?",
        [userId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });
            if (results.length === 0) return res.json({ success: false, message: "User not found" });

            res.json({ success: true, user: results[0] });
        }
    );
});

app.get("/users/:userId/fcmToken", (req, res) => {
    const { userId } = req.params;

    db.query(
        "SELECT fcmToken FROM users WHERE uid = ?",
        [userId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });

            if (results.length === 0) {
                return res.json({ success: false, message: "User not found" });
            }

            res.json({ 
                success: true, 
                fcmToken: results[0].fcmToken || "" 
            });
        }
    );
});

app.post("/users/updateFcmToken", (req, res) => {
    const { userId, fcmToken } = req.body;

    if (!userId || !fcmToken) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    db.query(
        "UPDATE users SET fcmToken = ? WHERE uid = ?",
        [fcmToken, userId],
        (err) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, message: "FCM token updated" });
        }
    );
});

// ======================================================
// USER SEARCH ENDPOINT
// ======================================================

app.post("/users/search", (req, res) => {
    const { currentUserId, query, filter } = req.body;

    console.log(`🔍 Search request - User: ${currentUserId}, Query: "${query}", Filter: ${filter}`);

    if (!currentUserId || !query) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    const searchPattern = `${query.toLowerCase()}%`;

    let sqlQuery;
    let queryParams;

    switch (filter) {
        case "Followers":
            sqlQuery = `
                SELECT DISTINCT u.uid, u.username, u.name, u.email, u.profileImage, 
                       u.bio, u.followersCount, u.followingCount, u.postCount
                FROM users u
                INNER JOIN followers f ON u.uid = f.followerId
                WHERE f.userId = ?
                AND u.uid != ?
                AND u.username_lower LIKE ?
                ORDER BY u.username
                LIMIT 50`;
            queryParams = [currentUserId, currentUserId, searchPattern];
            break;

        case "Following":
            sqlQuery = `
                SELECT DISTINCT u.uid, u.username, u.name, u.email, u.profileImage,
                       u.bio, u.followersCount, u.followingCount, u.postCount
                FROM users u
                INNER JOIN followers f ON u.uid = f.userId
                WHERE f.followerId = ?
                AND u.uid != ?
                AND u.username_lower LIKE ?
                ORDER BY u.username
                LIMIT 50`;
            queryParams = [currentUserId, currentUserId, searchPattern];
            break;

        case "All":
        default:
            sqlQuery = `
                SELECT uid, username, name, email, profileImage, bio,
                       followersCount, followingCount, postCount
                FROM users
                WHERE uid != ?
                AND username_lower LIKE ?
                ORDER BY username
                LIMIT 50`;
            queryParams = [currentUserId, searchPattern];
            break;
    }

    db.query(sqlQuery, queryParams, (err, results) => {
        if (err) {
            console.error("Search error:", err);
            return res.json({ success: false, message: err.message });
        }

        console.log(`✅ Found ${results.length} users for query "${query}" with filter "${filter}"`);

        res.json({
            success: true,
            users: results,
            count: results.length
        });
    });
});

// ======================================================
// FOLLOWERS/FOLLOWING ENDPOINTS
// ======================================================

app.post("/users/follow", (req, res) => {
    const { currentUserId, targetUserId } = req.body;

    if (!currentUserId || !targetUserId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    if (currentUserId === targetUserId) {
        return res.json({ success: false, message: "Cannot follow yourself" });
    }

    const timestamp = Date.now();

    db.query(
        "INSERT INTO followers (userId, followerId, timestamp) VALUES (?, ?, ?)",
        [targetUserId, currentUserId, timestamp],
        (err) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.json({ success: false, message: "Already following" });
                }
                return res.json({ success: false, message: err.message });
            }

            db.query(
                "UPDATE users SET followersCount = followersCount + 1 WHERE uid = ?",
                [targetUserId]
            );
            db.query(
                "UPDATE users SET followingCount = followingCount + 1 WHERE uid = ?",
                [currentUserId]
            );

            res.json({ success: true, message: "User followed successfully" });
        }
    );
});

app.post("/users/unfollow", (req, res) => {
    const { currentUserId, targetUserId } = req.body;

    if (!currentUserId || !targetUserId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    db.query(
        "DELETE FROM followers WHERE userId = ? AND followerId = ?",
        [targetUserId, currentUserId],
        (err, result) => {
            if (err) {
                return res.json({ success: false, message: err.message });
            }

            if (result.affectedRows === 0) {
                return res.json({ success: false, message: "Not following this user" });
            }

            db.query(
                "UPDATE users SET followersCount = GREATEST(followersCount - 1, 0) WHERE uid = ?",
                [targetUserId]
            );
            db.query(
                "UPDATE users SET followingCount = GREATEST(followingCount - 1, 0) WHERE uid = ?",
                [currentUserId]
            );

            res.json({ success: true, message: "User unfollowed successfully" });
        }
    );
});

app.post("/users/isFollowing", (req, res) => {
    const { currentUserId, targetUserId } = req.body;

    if (!currentUserId || !targetUserId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    db.query(
        "SELECT * FROM followers WHERE userId = ? AND followerId = ?",
        [targetUserId, currentUserId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, isFollowing: results.length > 0 });
        }
    );
});

app.get("/users/:userId/followers", (req, res) => {
    const { userId } = req.params;

    db.query(
        `SELECT u.uid, u.username, u.name, u.profileImage, u.bio
         FROM users u
         INNER JOIN followers f ON u.uid = f.followerId
         WHERE f.userId = ?
         ORDER BY f.timestamp DESC`,
        [userId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, followers: results });
        }
    );
});

app.get("/users/:userId/following", (req, res) => {
    const { userId } = req.params;

    db.query(
        `SELECT u.uid, u.username, u.name, u.profileImage, u.bio
         FROM users u
         INNER JOIN followers f ON u.uid = f.userId
         WHERE f.followerId = ?
         ORDER BY f.timestamp DESC`,
        [userId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, following: results });
        }
    );
});

// ======================================================
// FOLLOW REQUEST ENDPOINTS
// ======================================================

app.post("/users/sendFollowRequest", (req, res) => {
    const { currentUserId, targetUserId } = req.body;

    if (!currentUserId || !targetUserId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    if (currentUserId === targetUserId) {
        return res.json({ success: false, message: "Cannot send request to yourself" });
    }

    const timestamp = Date.now();

    db.query(
        "SELECT * FROM followers WHERE userId = ? AND followerId = ?",
        [targetUserId, currentUserId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });

            if (results.length > 0) {
                return res.json({ success: false, message: "Already following" });
            }

            db.query(
                "INSERT INTO follow_requests (senderId, receiverId, timestamp, status) VALUES (?, ?, ?, 'pending')",
                [currentUserId, targetUserId, timestamp],
                (err) => {
                    if (err) {
                        if (err.code === 'ER_DUP_ENTRY') {
                            return res.json({ success: false, message: "Request already sent" });
                        }
                        return res.json({ success: false, message: err.message });
                    }

                    console.log(`✅ Follow request: ${currentUserId} → ${targetUserId}`);
                    res.json({ success: true, message: "Follow request sent successfully" });
                }
            );
        }
    );
});

app.post("/users/cancelFollowRequest", (req, res) => {
    const { currentUserId, targetUserId } = req.body;

    if (!currentUserId || !targetUserId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    db.query(
        "DELETE FROM follow_requests WHERE senderId = ? AND receiverId = ? AND status = 'pending'",
        [currentUserId, targetUserId],
        (err, result) => {
            if (err) return res.json({ success: false, message: err.message });

            if (result.affectedRows === 0) {
                return res.json({ success: false, message: "No pending request found" });
            }

            console.log(`✅ Follow request cancelled: ${currentUserId} → ${targetUserId}`);
            res.json({ success: true, message: "Request cancelled successfully" });
        }
    );
});

app.post("/users/acceptFollowRequest", (req, res) => {
    const { currentUserId, requesterId } = req.body;

    if (!currentUserId || !requesterId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    db.query(
        "SELECT * FROM follow_requests WHERE senderId = ? AND receiverId = ? AND status = 'pending'",
        [requesterId, currentUserId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });

            if (results.length === 0) {
                return res.json({ success: false, message: "No pending request found" });
            }

            const timestamp = Date.now();

            db.query("START TRANSACTION", (err) => {
                if (err) return res.json({ success: false, message: err.message });

                db.query(
                    "INSERT INTO followers (userId, followerId, timestamp) VALUES (?, ?, ?)",
                    [currentUserId, requesterId, timestamp],
                    (err) => {
                        if (err) {
                            db.query("ROLLBACK");
                            return res.json({ success: false, message: err.message });
                        }

                        db.query(
                            "UPDATE users SET followersCount = followersCount + 1 WHERE uid = ?",
                            [currentUserId],
                            (err) => {
                                if (err) {
                                    db.query("ROLLBACK");
                                    return res.json({ success: false, message: err.message });
                                }

                                db.query(
                                    "UPDATE users SET followingCount = followingCount + 1 WHERE uid = ?",
                                    [requesterId],
                                    (err) => {
                                        if (err) {
                                            db.query("ROLLBACK");
                                            return res.json({ success: false, message: err.message });
                                        }

                                        db.query(
                                            "UPDATE follow_requests SET status = 'accepted' WHERE senderId = ? AND receiverId = ?",
                                            [requesterId, currentUserId],
                                            (err) => {
                                                if (err) {
                                                    db.query("ROLLBACK");
                                                    return res.json({ success: false, message: err.message });
                                                }

                                                db.query("COMMIT", (err) => {
                                                    if (err) {
                                                        db.query("ROLLBACK");
                                                        return res.json({ success: false, message: err.message });
                                                    }

                                                    console.log(`✅ Follow request accepted: ${requesterId} → ${currentUserId}`);
                                                    res.json({ success: true, message: "Request accepted successfully" });
                                                });
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    }
                );
            });
        }
    );
});

app.post("/users/rejectFollowRequest", (req, res) => {
    const { currentUserId, requesterId } = req.body;

    if (!currentUserId || !requesterId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    db.query(
        "UPDATE follow_requests SET status = 'rejected' WHERE senderId = ? AND receiverId = ? AND status = 'pending'",
        [requesterId, currentUserId],
        (err, result) => {
            if (err) return res.json({ success: false, message: err.message });

            if (result.affectedRows === 0) {
                return res.json({ success: false, message: "No pending request found" });
            }

            console.log(`✅ Follow request rejected: ${requesterId} → ${currentUserId}`);
            res.json({ success: true, message: "Request rejected successfully" });
        }
    );
});

app.post("/users/isRequestPending", (req, res) => {
    const { currentUserId, targetUserId } = req.body;

    if (!currentUserId || !targetUserId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    db.query(
        "SELECT * FROM follow_requests WHERE senderId = ? AND receiverId = ? AND status = 'pending'",
        [currentUserId, targetUserId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, isPending: results.length > 0 });
        }
    );
});

app.get("/users/:userId/receivedRequests", (req, res) => {
    const { userId } = req.params;

    db.query(
        `SELECT fr.id, fr.senderId, fr.timestamp, u.username, u.name, u.profileImage, u.bio
         FROM follow_requests fr
         INNER JOIN users u ON fr.senderId = u.uid
         WHERE fr.receiverId = ? AND fr.status = 'pending'
         ORDER BY fr.timestamp DESC`,
        [userId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, requests: results });
        }
    );
});

app.get("/users/:userId/sentRequests", (req, res) => {
    const { userId } = req.params;

    db.query(
        `SELECT fr.id, fr.receiverId, fr.timestamp, u.username, u.name, u.profileImage, u.bio
         FROM follow_requests fr
         INNER JOIN users u ON fr.receiverId = u.uid
         WHERE fr.senderId = ? AND fr.status = 'pending'
         ORDER BY fr.timestamp DESC`,
        [userId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, requests: results });
        }
    );
});

// ======================================================
// STORY ENDPOINTS
// ======================================================

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

// ======================================================
// POST ENDPOINTS
// ======================================================

app.post("/posts/upload", (req, res) => {
    let { postId, userId, username, profileImage, images, caption, location, timestamp } = req.body;

    if (!userId || !images || images.length === 0) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    if (!postId) {
        postId = require('uuid').v4();
    }

    if (!timestamp) {
        timestamp = Date.now();
    }

    db.query(
        `INSERT INTO posts (postId, userId, username, profileImage, images, caption, location, timestamp)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [postId, userId, username || "", profileImage || "", JSON.stringify(images), caption || "", location || "", timestamp],
        (err) => {
            if (err) {
                console.error("Post upload error:", err);
                return res.json({ success: false, message: err.message });
            }
            console.log(`✅ Post uploaded: ${postId} by ${username}`);
            res.json({ success: true, message: "Post uploaded successfully", postId });
        }
    );
});

app.get("/posts/all", (req, res) => {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    const query = `
        SELECT postId, userId, username, profileImage, images, caption, location, timestamp, likesCount, commentsCount
        FROM posts
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?`;

    db.query(query, [limit, offset], (err, results) => {
        if (err) {
            console.error("Error fetching posts:", err);
            return res.json({ success: false, message: err.message });
        }

        const posts = results.map(post => {
            let images = [];
            if (Array.isArray(post.images)) {
                images = post.images;
            } else if (typeof post.images === 'string') {
                try {
                    images = JSON.parse(post.images);
                } catch (e) {
                    images = [post.images];
                }
            }

            return {
                postId: post.postId,
                userId: post.userId,
                username: post.username,
                profileImage: post.profileImage || "",
                images: images,
                caption: post.caption || "",
                location: post.location || "",
                timestamp: post.timestamp,
                likesCount: post.likesCount || 0,
                commentsCount: post.commentsCount || 0
            };
        });

        console.log(`✅ Fetched ${posts.length} posts (limit: ${limit}, offset: ${offset})`);
        res.json({ success: true, posts, limit, offset });
    });
});

app.get("/posts/user/:userId", (req, res) => {
    const { userId } = req.params;

    db.query(
        `SELECT * FROM posts WHERE userId = ? ORDER BY timestamp DESC`,
        [userId],
        (err, results) => {
            if (err) {
                console.error("Error fetching user posts:", err);
                return res.json({ success: false, message: err.message });
            }

            const posts = results.map(post => {
                let images = [];
                
                if (Array.isArray(post.images)) {
                    images = post.images;
                } else if (typeof post.images === 'string') {
                    try {
                        images = JSON.parse(post.images);
                    } catch (e) {
                        images = [post.images];
                    }
                }

                return {
                    postId: post.postId,
                    userId: post.userId,
                    username: post.username,
                    profileImage: post.profileImage || "",
                    images: images,
                    caption: post.caption || "",
                    location: post.location || "",
                    timestamp: post.timestamp,
                    likesCount: post.likesCount || 0,
                    commentsCount: post.commentsCount || 0
                };
            });

            res.json({ success: true, posts });
        }
    );
});



// Add this to your server.js after the other table creations

// ======================================================
// CREATE NOTIFICATIONS TABLE
// ======================================================

const createNotificationsTable = `
CREATE TABLE IF NOT EXISTS notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userId VARCHAR(255) NOT NULL,
    fromUserId VARCHAR(255) NOT NULL,
    fromUsername VARCHAR(255) NOT NULL,
    fromProfileImage TEXT,
    message TEXT NOT NULL,
    type VARCHAR(50) NOT NULL,
    postImage TEXT,
    timestamp BIGINT NOT NULL,
    isRead BOOLEAN DEFAULT FALSE,
    INDEX idx_user (userId),
    INDEX idx_timestamp (timestamp DESC),
    INDEX idx_read (isRead)
)`;

db.query(createNotificationsTable, (err) => {
    if (err) console.error("Error creating notifications table:", err);
    else console.log("✅ Notifications table ready");
});

// ======================================================
// NOTIFICATION ENDPOINTS
// ======================================================

// Get notifications for a user
// ======================================================
// UPDATED NOTIFICATION ENDPOINT - INCLUDES FOLLOW REQUESTS
// Replace the existing /notifications/:userId endpoint with this one
// ======================================================

app.get("/notifications/:userId", (req, res) => {
    const { userId } = req.params;
    const includeRead = req.query.includeRead === 'true';

    console.log(`📬 Fetching notifications for user: ${userId}, includeRead: ${includeRead}`);

    // First, get regular notifications
    let notificationsQuery = `
        SELECT 
            id as notificationId,
            userId,
            fromUserId,
            fromUsername,
            fromProfileImage,
            message,
            type,
            postImage,
            timestamp,
            isRead
        FROM notifications 
        WHERE userId = ?`;
    
    if (!includeRead) {
        notificationsQuery += ` AND isRead = FALSE`;
    }

    // Then, get pending follow requests
    const followRequestsQuery = `
        SELECT 
            fr.id as notificationId,
            fr.receiverId as userId,
            fr.senderId as fromUserId,
            u.username as fromUsername,
            u.profileImage as fromProfileImage,
            'sent you a follow request' as message,
            'follow_request' as type,
            NULL as postImage,
            fr.timestamp,
            FALSE as isRead
        FROM follow_requests fr
        INNER JOIN users u ON fr.senderId = u.uid
        WHERE fr.receiverId = ? AND fr.status = 'pending'`;

    // Execute both queries
    db.query(notificationsQuery, [userId], (err, notificationResults) => {
        if (err) {
            console.error("Error fetching notifications:", err);
            return res.json({ success: false, message: err.message });
        }

        db.query(followRequestsQuery, [userId], (err, followRequestResults) => {
            if (err) {
                console.error("Error fetching follow requests:", err);
                return res.json({ success: false, message: err.message });
            }

            // Combine both results
            const allNotifications = [...notificationResults, ...followRequestResults];

            // Sort by timestamp (most recent first)
            allNotifications.sort((a, b) => b.timestamp - a.timestamp);

            // Limit to 50 most recent
            const limitedNotifications = allNotifications.slice(0, 50);

            console.log(`✅ Fetched ${notificationResults.length} regular notifications and ${followRequestResults.length} follow requests for user: ${userId}`);
            console.log(`Total: ${limitedNotifications.length} notifications`);

            res.json({ 
                success: true, 
                notifications: limitedNotifications,
                count: limitedNotifications.length
            });
        });
    });
});

// Create notification (called internally by other endpoints)
function createNotification(userId, fromUserId, fromUsername, fromProfileImage, message, type, postImage = null) {
    const timestamp = Date.now();
    
    db.query(
        `INSERT INTO notifications (userId, fromUserId, fromUsername, fromProfileImage, message, type, postImage, timestamp)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [userId, fromUserId, fromUsername, fromProfileImage, message, type, postImage, timestamp],
        (err) => {
            if (err) {
                console.error("Error creating notification:", err);
            } else {
                console.log(`✅ Notification created: ${type} from ${fromUsername} to ${userId}`);
            }
        }
    );
}

// Mark notification as read
app.post("/notifications/markRead", (req, res) => {
    const { notificationId } = req.body;

    if (!notificationId) {
        return res.json({ success: false, message: "Missing notification ID" });
    }

    db.query(
        "UPDATE notifications SET isRead = TRUE WHERE id = ?",
        [notificationId],
        (err) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, message: "Notification marked as read" });
        }
    );
});

// Mark all notifications as read for a user
app.post("/notifications/markAllRead", (req, res) => {
    const { userId } = req.body;

    if (!userId) {
        return res.json({ success: false, message: "Missing user ID" });
    }

    db.query(
        "UPDATE notifications SET isRead = TRUE WHERE userId = ? AND isRead = FALSE",
        [userId],
        (err, result) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ 
                success: true, 
                message: `Marked ${result.affectedRows} notifications as read` 
            });
        }
    );
});

// Delete notification
app.delete("/notifications/:notificationId", (req, res) => {
    const { notificationId } = req.params;

    db.query(
        "DELETE FROM notifications WHERE id = ?",
        [notificationId],
        (err) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, message: "Notification deleted" });
        }
    );
});

// ======================================================
// UPDATE FOLLOW REQUEST ENDPOINTS TO CREATE NOTIFICATIONS
// ======================================================

// Modify the sendFollowRequest endpoint to create a notification
app.post("/users/sendFollowRequest", (req, res) => {
    const { currentUserId, targetUserId } = req.body;

    if (!currentUserId || !targetUserId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    if (currentUserId === targetUserId) {
        return res.json({ success: false, message: "Cannot send request to yourself" });
    }

    const timestamp = Date.now();

    // First check if already following
    db.query(
        "SELECT * FROM followers WHERE userId = ? AND followerId = ?",
        [targetUserId, currentUserId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });

            if (results.length > 0) {
                return res.json({ success: false, message: "Already following" });
            }

            // Insert follow request
            db.query(
                "INSERT INTO follow_requests (senderId, receiverId, timestamp, status) VALUES (?, ?, ?, 'pending')",
                [currentUserId, targetUserId, timestamp],
                (err) => {
                    if (err) {
                        if (err.code === 'ER_DUP_ENTRY') {
                            return res.json({ success: false, message: "Request already sent" });
                        }
                        return res.json({ success: false, message: err.message });
                    }

                    // Get sender info to create notification
                    db.query(
                        "SELECT username, profileImage FROM users WHERE uid = ?",
                        [currentUserId],
                        (err, userResults) => {
                            if (err || userResults.length === 0) {
                                console.log(`✅ Follow request sent (notification creation failed): ${currentUserId} → ${targetUserId}`);
                                return res.json({ success: true, message: "Follow request sent successfully" });
                            }

                            const sender = userResults[0];
                            
                            // Create notification
                            createNotification(
                                targetUserId,
                                currentUserId,
                                sender.username,
                                sender.profileImage || "",
                                "sent you a follow request",
                                "follow_request"
                            );

                            console.log(`✅ Follow request sent with notification: ${currentUserId} → ${targetUserId}`);
                            res.json({ success: true, message: "Follow request sent successfully" });
                        }
                    );
                }
            );
        }
    );
});

// Modify acceptFollowRequest to remove the notification
app.post("/users/acceptFollowRequest", (req, res) => {
    const { currentUserId, requesterId } = req.body;

    if (!currentUserId || !requesterId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    db.query(
        "SELECT * FROM follow_requests WHERE senderId = ? AND receiverId = ? AND status = 'pending'",
        [requesterId, currentUserId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });

            if (results.length === 0) {
                return res.json({ success: false, message: "No pending request found" });
            }

            const timestamp = Date.now();

            db.query("START TRANSACTION", (err) => {
                if (err) return res.json({ success: false, message: err.message });

                // Add follower relationship
                db.query(
                    "INSERT INTO followers (userId, followerId, timestamp) VALUES (?, ?, ?)",
                    [currentUserId, requesterId, timestamp],
                    (err) => {
                        if (err) {
                            db.query("ROLLBACK");
                            return res.json({ success: false, message: err.message });
                        }

                        // Update follower count
                        db.query(
                            "UPDATE users SET followersCount = followersCount + 1 WHERE uid = ?",
                            [currentUserId],
                            (err) => {
                                if (err) {
                                    db.query("ROLLBACK");
                                    return res.json({ success: false, message: err.message });
                                }

                                // Update following count
                                db.query(
                                    "UPDATE users SET followingCount = followingCount + 1 WHERE uid = ?",
                                    [requesterId],
                                    (err) => {
                                        if (err) {
                                            db.query("ROLLBACK");
                                            return res.json({ success: false, message: err.message });
                                        }

                                        // Update request status
                                        db.query(
                                            "UPDATE follow_requests SET status = 'accepted' WHERE senderId = ? AND receiverId = ?",
                                            [requesterId, currentUserId],
                                            (err) => {
                                                if (err) {
                                                    db.query("ROLLBACK");
                                                    return res.json({ success: false, message: err.message });
                                                }

                                                // Delete notification
                                                db.query(
                                                    "DELETE FROM notifications WHERE userId = ? AND fromUserId = ? AND type = 'follow_request'",
                                                    [currentUserId, requesterId],
                                                    (err) => {
                                                        if (err) {
                                                            console.error("Error deleting notification:", err);
                                                        }

                                                        db.query("COMMIT", (err) => {
                                                            if (err) {
                                                                db.query("ROLLBACK");
                                                                return res.json({ success: false, message: err.message });
                                                            }

                                                            console.log(`✅ Follow request accepted: ${requesterId} → ${currentUserId}`);
                                                            res.json({ success: true, message: "Request accepted successfully" });
                                                        });
                                                    }
                                                );
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    }
                );
            });
        }
    );
});

// Modify rejectFollowRequest to remove the notification
app.post("/users/rejectFollowRequest", (req, res) => {
    const { currentUserId, requesterId } = req.body;

    if (!currentUserId || !requesterId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    db.query(
        "UPDATE follow_requests SET status = 'rejected' WHERE senderId = ? AND receiverId = ? AND status = 'pending'",
        [requesterId, currentUserId],
        (err, result) => {
            if (err) return res.json({ success: false, message: err.message });

            if (result.affectedRows === 0) {
                return res.json({ success: false, message: "No pending request found" });
            }

            // Delete notification
            db.query(
                "DELETE FROM notifications WHERE userId = ? AND fromUserId = ? AND type = 'follow_request'",
                [currentUserId, requesterId],
                (err) => {
                    if (err) {
                        console.error("Error deleting notification:", err);
                    }

                    console.log(`✅ Follow request rejected: ${requesterId} → ${currentUserId}`);
                    res.json({ success: true, message: "Request rejected successfully" });
                }
            );
        }
    );
});


// UPDATE user profile
app.put("/users/update", (req, res) => {
    const { userId, username, name, lastname, bio, website, phone, gender, profileImage } = req.body;

    if (!userId) {
        return res.json({ success: false, message: "User ID required" });
    }

    // Check if username is being changed and if it's already taken by another user
    const checkUsernameQuery = username 
        ? "SELECT * FROM users WHERE username = ? AND uid != ?"
        : null;

    const executeUpdate = () => {
        const updates = [];
        const values = [];

        if (username !== undefined) {
            updates.push("username = ?");
            values.push(username);
            updates.push("username_lower = ?");
            values.push(username.toLowerCase());
        }
        if (name !== undefined) {
            updates.push("name = ?");
            values.push(name);
        }
        if (lastname !== undefined) {
            updates.push("lastname = ?");
            values.push(lastname);
        }
        if (bio !== undefined) {
            updates.push("bio = ?");
            values.push(bio);
        }
        if (website !== undefined) {
            updates.push("website = ?");
            values.push(website);
        }
        if (phone !== undefined) {
            updates.push("phone = ?");
            values.push(phone);
        }
        if (gender !== undefined) {
            updates.push("gender = ?");
            values.push(gender);
        }
        if (profileImage !== undefined) {
            updates.push("profileImage = ?");
            values.push(profileImage);
            updates.push("profilePicture = ?");
            values.push(profileImage);
        }

        values.push(userId);

        if (updates.length === 0) {
            return res.json({ success: false, message: "No fields to update" });
        }

        const query = `UPDATE users SET ${updates.join(", ")} WHERE uid = ?`;

        db.query(query, values, (err, result) => {
            if (err) {
                console.error("Update error:", err);
                return res.json({ success: false, message: "Failed to update profile" });
            }

            // Fetch updated user data
            db.query(
                "SELECT uid, username, email, name, lastname, bio, website, phone, gender, profileImage, profilePicture, followersCount, followingCount, postCount FROM users WHERE uid = ?",
                [userId],
                (err, results) => {
                    if (err) return res.json({ success: false, message: "Database error" });
                    
                    console.log(`✅ Profile updated for user ${userId}`);
                    res.json({ success: true, message: "Profile updated successfully", user: results[0] });
                }
            );
        });
    };

    // If username is being changed, check if it's available
    if (checkUsernameQuery) {
        db.query(checkUsernameQuery, [username, userId], (err, results) => {
            if (err) return res.json({ success: false, message: "Database error" });
            if (results.length > 0) {
                return res.json({ success: false, message: "Username already taken" });
            }
            executeUpdate();
        });
    } else {
        executeUpdate();
    }
});


// ======================================================
// GLOBAL ERROR HANDLING
// ======================================================

process.on('uncaughtException', err => console.error('Uncaught Exception:', err));
process.on('unhandledRejection', err => console.error('Unhandled Rejection:', err));

// ======================================================
// START SERVER
// ======================================================

app.listen(process.env.PORT || 3000, () => {
    console.log(`🚀 Server running on port ${process.env.PORT || 3000}`);
});