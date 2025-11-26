// server.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
const session = require('express-session');


// Add this at the top of your server.js after other requires
const admin = require('firebase-admin');


const serviceAccount = JSON.parse(
  Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT, "base64").toString("utf-8")
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

console.log("✅ Firebase loaded from Railway environment variable");





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
// DATABASE CONNECTION
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

// Users table
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

// Posts table
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

// Stories table
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

// Followers table
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

// Follow requests table
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

// Messages table
db.query(`
CREATE TABLE IF NOT EXISTS messages (
    messageId VARCHAR(255) PRIMARY KEY,
    senderId VARCHAR(255) NOT NULL,
    receiverId VARCHAR(255) NOT NULL,
    chatId VARCHAR(255) NOT NULL,
    messageText TEXT,
    imageData LONGTEXT,
    timestamp BIGINT NOT NULL,
    isEdited BOOLEAN DEFAULT FALSE,
    isSystemMessage BOOLEAN DEFAULT FALSE,
    isVanishMode BOOLEAN DEFAULT FALSE,
    seenAt BIGINT,
    INDEX idx_chatId (chatId),
    INDEX idx_timestamp (timestamp),
    INDEX idx_senderId (senderId),
    INDEX idx_receiverId (receiverId)
)`, (err) => {
    if (err) console.error("Error creating messages table:", err);
    else console.log("✅ Messages table ready");
});

// Conversations table
db.query(`
CREATE TABLE IF NOT EXISTS conversations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userId VARCHAR(255) NOT NULL,
    otherUserId VARCHAR(255) NOT NULL,
    otherUsername VARCHAR(255),
    otherUserImage LONGTEXT,
    lastMessage TEXT,
    timestamp BIGINT NOT NULL,
    unreadCount INT DEFAULT 0,
    UNIQUE KEY unique_conversation (userId, otherUserId),
    INDEX idx_userId (userId),
    INDEX idx_timestamp (timestamp)
)`, (err) => {
    if (err) console.error("Error creating conversations table:", err);
    else console.log("✅ Conversations table ready");
});

// Notifications table (your existing one)
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

// NEW: Pending notifications table for polling system
const createPendingNotificationsTable = `
CREATE TABLE IF NOT EXISTS pending_notifications (
    notification_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    sender_id VARCHAR(255) NOT NULL,
    sender_username VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    extra_data JSON,
    timestamp BIGINT NOT NULL,
    delivered BOOLEAN DEFAULT FALSE,
    INDEX idx_user_delivered (user_id, delivered),
    INDEX idx_timestamp (timestamp DESC)
)`;

db.query(createPendingNotificationsTable, (err) => {
    if (err) console.error("Error creating pending_notifications table:", err);
    else console.log("✅ Pending notifications table ready");
});

// Call requests table
const createCallRequestsTable = `
CREATE TABLE IF NOT EXISTS call_requests (
    call_id VARCHAR(255) PRIMARY KEY,
    caller_id VARCHAR(255) NOT NULL,
    caller_name VARCHAR(255) NOT NULL,
    caller_profile_image LONGTEXT,
    receiver_id VARCHAR(255) NOT NULL,
    channel_name VARCHAR(255) NOT NULL,
    call_type ENUM('voice', 'video') NOT NULL,
    status ENUM('calling', 'accepted', 'rejected', 'ended') DEFAULT 'calling',
    timestamp BIGINT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_receiver (receiver_id, status),
    INDEX idx_caller (caller_id),
    INDEX idx_timestamp (timestamp DESC)
)`;

db.query(createCallRequestsTable, (err) => {
    if (err) console.error("Error creating call_requests table:", err);
    else console.log("✅ Call requests table ready");
});

// User presence table
const createUserPresenceTable = `
CREATE TABLE IF NOT EXISTS user_presence (
    user_id VARCHAR(255) PRIMARY KEY,
    is_online BOOLEAN DEFAULT FALSE,
    last_seen BIGINT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_online (is_online)
)`;

db.query(createUserPresenceTable, (err) => {
    if (err) console.error("Error creating user_presence table:", err);
    else console.log("✅ User presence table ready");
});

// Comments table
const createCommentsTable = `
CREATE TABLE IF NOT EXISTS comments (
    commentId VARCHAR(255) PRIMARY KEY,
    postId VARCHAR(255) NOT NULL,
    userId VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    profileImage TEXT,
    text TEXT NOT NULL,
    timestamp BIGINT NOT NULL,
    INDEX idx_post (postId),
    INDEX idx_user (userId),
    INDEX idx_timestamp (timestamp DESC)
)`;

db.query(createCommentsTable, (err) => {
    if (err) console.error("Error creating comments table:", err);
    else console.log("✅ Comments table ready");
});

// Likes table
const createLikesTable = `
CREATE TABLE IF NOT EXISTS likes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    postId VARCHAR(255) NOT NULL,
    userId VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    timestamp BIGINT NOT NULL,
    UNIQUE KEY unique_like (postId, userId),
    INDEX idx_post (postId),
    INDEX idx_user (userId)
)`;

db.query(createLikesTable, (err) => {
    if (err) console.error("Error creating likes table:", err);
    else console.log("✅ Likes table ready");
});

// Screenshot events table
const createScreenshotEventsTable = `
CREATE TABLE IF NOT EXISTS screenshot_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    chatId VARCHAR(255) NOT NULL,
    userId VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    timestamp BIGINT NOT NULL,
    INDEX idx_chatId (chatId),
    INDEX idx_timestamp (timestamp DESC)
)`;

db.query(createScreenshotEventsTable, (err) => {
    if (err) console.error("Error creating screenshot_events table:", err);
    else console.log("✅ Screenshot events table ready");
});

// ======================================================
// HELPER FUNCTIONS
// ======================================================

// ======================================================
// FCM HELPER FUNCTIONS
// ======================================================

/**
 * Send FCM notification to a specific user
 */
async function sendFCMNotification(userId, title, body, data = {}) {
    try {
        // Get user's FCM token
        const result = await new Promise((resolve, reject) => {
            db.query(
                "SELECT fcmToken FROM users WHERE uid = ?",
                [userId],
                (err, results) => {
                    if (err) reject(err);
                    else resolve(results);
                }
            );
        });

        if (result.length === 0 || !result[0].fcmToken) {
            console.log(`⚠️ No FCM token for user ${userId}`);
            return false;
        }

        const fcmToken = result[0].fcmToken;

        // Prepare FCM message
        const message = {
            token: fcmToken,
            notification: {
                title: title,
                body: body
            },
            data: {
                ...data,
                timestamp: Date.now().toString()
            },
            android: {
                priority: 'high',
                notification: {
                    sound: 'default',
                    channelId: 'socially_notifications'
                }
            }
        };

        // Send notification
        const response = await admin.messaging().send(message);
        console.log(`FCM sent to ${userId}: ${response}`);
return true;

} catch (error) {
    console.error(`❌ Error sending FCM to ${userId}:`, error);

    if (
        error.code === 'messaging/invalid-registration-token' || 
        error.code === 'messaging/registration-token-not-registered'
    ) {
        db.query("UPDATE users SET fcmToken = '' WHERE uid = ?", [userId]);
        console.log(`🗑️ Cleared invalid FCM token for user ${userId}`);
    }

        
        return false;
    }
}


function generateUniqueUid() {
    return Date.now().toString() + Math.random().toString(36).substr(2, 9);
}

// NEW: Create pending notification
function createPendingNotification(userId, senderId, senderUsername, type, message, extraData = null) {
    const timestamp = Date.now();
   
    db.query(
        `INSERT INTO pending_notifications (user_id, sender_id, sender_username, type, message, extra_data, timestamp)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [userId, senderId, senderUsername, type, message, extraData ? JSON.stringify(extraData) : null, timestamp],
        (err) => {
            if (err) {
                console.error("❌ Error creating pending notification:", err);
            } else {
                console.log(`✅ Pending notification created: ${type} for ${userId}`);
            }
        }
    );
}

// Existing createNotification function (for your notifications screen)
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

// ======================================================
// AUTHENTICATION ROUTES
// ======================================================

app.post("/register", (req, res) => {
    const { username, name, lastname, email, password, dob, profileImage } = req.body;

    console.log("📝 Registration attempt:", { username, email, name, lastname });

    if (!username || !name || !lastname || !email || !password) {
        return res.json({ success: false, message: "Required fields missing" });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.json({ success: false, message: "Invalid email format" });
    }

    const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
    if (!usernameRegex.test(username)) {
        return res.json({ success: false, message: "Username must be 3-30 characters (letters, numbers, underscores only)" });
    }

    if (password.length < 6) {
        return res.json({ success: false, message: "Password must be at least 6 characters" });
    }

    db.query(
        "SELECT * FROM users WHERE email = ? OR username = ?",
        [email, username],
        (err, results) => {
            if (err) {
                return res.json({ success: false, message: "Database error: " + err.message });
            }

            if (results.length > 0) {
                const existingUser = results[0];
                if (existingUser.email === email) {
                    return res.json({ success: false, message: "Email already registered" });
                }
                if (existingUser.username === username) {
                    return res.json({ success: false, message: "Username already taken" });
                }
            }

            const uid = generateUniqueUid();

            const insertQuery = `
                INSERT INTO users
                (uid, username, username_lower, name, lastname, email, password, dob, profileImage,
                 profilePicture, bio, website, followersCount, followingCount, postCount, fcmToken)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', '', 0, 0, 0, '')`;

            const insertValues = [
                uid, username, username.toLowerCase(), name, lastname, email, password, dob || '', profileImage || ''
            ];

            db.query(insertQuery, insertValues, (err) => {
                if (err) {
                    return res.json({ success: false, message: "Registration failed: " + err.message });
                }

                console.log(`✅ User registered: ${username} (UID: ${uid})`);

                res.json({
                    success: true,
                    message: "Registration successful",
                    user: {
                        uid, username, username_lower: username.toLowerCase(), name, lastname, email,
                        dob: dob || '', profileImage: profileImage || '', profilePicture: '', bio: '', website: '',
                        followersCount: 0, followingCount: 0, postCount: 0
                    }
                });
            });
        }
    );
});

app.post("/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({ success: false, message: "Email and password required" });
    }

    db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
        if (err) {
            return res.json({ success: false, message: "Database error" });
        }

        if (results.length === 0) {
            return res.json({ success: false, message: "User not found" });
        }

        const user = results[0];
        if (password === String(user.password)) {
            const { password, ...userData } = user;
            return res.json({ success: true, message: "Login successful", user: userData });
        } else {
            return res.json({ success: false, message: "Invalid password" });
        }
    });
});

app.get("/session", (req, res) => {
    if (!req.session.userId) return res.json({ loggedIn: false });

    db.query("SELECT * FROM users WHERE uid = ?", [req.session.userId], (err, results) => {
        if (err || results.length === 0) return res.json({ loggedIn: false });

        const user = results[0];
        delete user.password;
        res.json({ loggedIn: true, user });
    });
});

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
            res.json({ success: true, fcmToken: results[0].fcmToken || "" });
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
            console.log(`✅ FCM token updated for user: ${userId}`);
            res.json({ success: true, message: "FCM token updated" });
        }
    );
});

app.post("/users/search", (req, res) => {
    const { currentUserId, query, filter } = req.body;

    if (!currentUserId || !query) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    const searchPattern = `${query.toLowerCase()}%`;
    let sqlQuery, queryParams;

    switch (filter) {
        case "Followers":
            sqlQuery = `SELECT DISTINCT u.uid, u.username, u.name, u.email, u.profileImage,
                       u.bio, u.followersCount, u.followingCount, u.postCount
                FROM users u INNER JOIN followers f ON u.uid = f.followerId
                WHERE f.userId = ? AND u.uid != ? AND u.username_lower LIKE ? ORDER BY u.username LIMIT 50`;
            queryParams = [currentUserId, currentUserId, searchPattern];
            break;
        case "Following":
            sqlQuery = `SELECT DISTINCT u.uid, u.username, u.name, u.email, u.profileImage,
                       u.bio, u.followersCount, u.followingCount, u.postCount
                FROM users u INNER JOIN followers f ON u.uid = f.userId
                WHERE f.followerId = ? AND u.uid != ? AND u.username_lower LIKE ? ORDER BY u.username LIMIT 50`;
            queryParams = [currentUserId, currentUserId, searchPattern];
            break;
        default:
            sqlQuery = `SELECT uid, username, name, email, profileImage, bio,
                       followersCount, followingCount, postCount FROM users
                WHERE uid != ? AND username_lower LIKE ? ORDER BY username LIMIT 50`;
            queryParams = [currentUserId, searchPattern];
    }

    db.query(sqlQuery, queryParams, (err, results) => {
        if (err) return res.json({ success: false, message: err.message });
        res.json({ success: true, users: results, count: results.length });
    });
});

app.put("/users/update", (req, res) => {
    const { userId, username, name, lastname, bio, website, phone, gender, profileImage } = req.body;

    if (!userId) {
        return res.json({ success: false, message: "User ID required" });
    }

    const executeUpdate = () => {
        const updates = [];
        const values = [];

        if (username !== undefined) {
            updates.push("username = ?", "username_lower = ?");
            values.push(username, username.toLowerCase());
        }
        if (name !== undefined) { updates.push("name = ?"); values.push(name); }
        if (lastname !== undefined) { updates.push("lastname = ?"); values.push(lastname); }
        if (bio !== undefined) { updates.push("bio = ?"); values.push(bio); }
        if (website !== undefined) { updates.push("website = ?"); values.push(website); }
        if (phone !== undefined) { updates.push("phone = ?"); values.push(phone); }
        if (gender !== undefined) { updates.push("gender = ?"); values.push(gender); }
        if (profileImage !== undefined) {
            updates.push("profileImage = ?", "profilePicture = ?");
            values.push(profileImage, profileImage);
        }

        values.push(userId);

        if (updates.length === 0) {
            return res.json({ success: false, message: "No fields to update" });
        }

        db.query(`UPDATE users SET ${updates.join(", ")} WHERE uid = ?`, values, (err) => {
            if (err) return res.json({ success: false, message: "Failed to update profile" });

            db.query(
                "SELECT uid, username, email, name, lastname, bio, website, phone, gender, profileImage, profilePicture, followersCount, followingCount, postCount FROM users WHERE uid = ?",
                [userId],
                (err, results) => {
                    if (err) return res.json({ success: false, message: "Database error" });
                    res.json({ success: true, message: "Profile updated successfully", user: results[0] });
                }
            );
        });
    };

    if (username) {
        db.query("SELECT * FROM users WHERE username = ? AND uid != ?", [username, userId], (err, results) => {
            if (err) return res.json({ success: false, message: "Database error" });
            if (results.length > 0) return res.json({ success: false, message: "Username already taken" });
            executeUpdate();
        });
    } else {
        executeUpdate();
    }
});

// ======================================================
// FOLLOWERS/FOLLOWING ENDPOINTS
// ======================================================

app.post("/users/follow", (req, res) => {
    const { currentUserId, targetUserId } = req.body;

    if (!currentUserId || !targetUserId || currentUserId === targetUserId) {
        return res.json({ success: false, message: "Invalid request" });
    }

    const timestamp = Date.now();

    db.query(
        "INSERT INTO followers (userId, followerId, timestamp) VALUES (?, ?, ?)",
        [targetUserId, currentUserId, timestamp],
        (err) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') return res.json({ success: false, message: "Already following" });
                return res.json({ success: false, message: err.message });
            }

            db.query("UPDATE users SET followersCount = followersCount + 1 WHERE uid = ?", [targetUserId]);
            db.query("UPDATE users SET followingCount = followingCount + 1 WHERE uid = ?", [currentUserId]);

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
            if (err) return res.json({ success: false, message: err.message });
            if (result.affectedRows === 0) return res.json({ success: false, message: "Not following this user" });

            db.query("UPDATE users SET followersCount = GREATEST(followersCount - 1, 0) WHERE uid = ?", [targetUserId]);
            db.query("UPDATE users SET followingCount = GREATEST(followingCount - 1, 0) WHERE uid = ?", [currentUserId]);

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

// Replace your existing followers/following GET endpoints with these:

app.get("/users/:userId/followers", (req, res) => {
    const { userId } = req.params;

    db.query(
        `SELECT u.uid as userId, u.username, u.name, u.lastname, u.profileImage, 
                u.profilePicture, u.bio, u.followersCount, u.followingCount, u.postCount
         FROM users u 
         INNER JOIN followers f ON u.uid = f.followerId
         WHERE f.userId = ? 
         ORDER BY f.timestamp DESC`,
        [userId],
        (err, results) => {
            if (err) {
                console.error("Error fetching followers:", err);
                return res.status(500).json([]);
            }
            
            // Map results to ensure consistent property names
            const followers = results.map(user => ({
                userId: user.userId,
                uid: user.userId,
                username: user.username,
                name: user.name || "",
                lastname: user.lastname || "",
                profileImage: user.profileImage || "",
                profilePicture: user.profilePicture || "",
                bio: user.bio || "",
                followersCount: user.followersCount || 0,
                followingCount: user.followingCount || 0,
                postCount: user.postCount || 0
            }));
            
            console.log(`✅ Found ${followers.length} followers for user ${userId}`);
            res.json(followers);
        }
    );
});

app.get("/users/:userId/following", (req, res) => {
    const { userId } = req.params;

    db.query(
        `SELECT u.uid as userId, u.username, u.name, u.lastname, u.profileImage, 
                u.profilePicture, u.bio, u.followersCount, u.followingCount, u.postCount
         FROM users u 
         INNER JOIN followers f ON u.uid = f.userId
         WHERE f.followerId = ? 
         ORDER BY f.timestamp DESC`,
        [userId],
        (err, results) => {
            if (err) {
                console.error("Error fetching following:", err);
                return res.status(500).json([]);
            }
            
            // Map results to ensure consistent property names
            const following = results.map(user => ({
                userId: user.userId,
                uid: user.userId,
                username: user.username,
                name: user.name || "",
                lastname: user.lastname || "",
                profileImage: user.profileImage || "",
                profilePicture: user.profilePicture || "",
                bio: user.bio || "",
                followersCount: user.followersCount || 0,
                followingCount: user.followingCount || 0,
                postCount: user.postCount || 0
            }));
            
            console.log(`✅ Found ${following.length} following for user ${userId}`);
            res.json(following);
        }
    );
});

// ======================================================
// FOLLOW REQUEST ENDPOINTS
// ======================================================

app.post("/users/sendFollowRequest", async (req, res) => {
    const { currentUserId, targetUserId } = req.body;

    if (!currentUserId || !targetUserId || currentUserId === targetUserId) {
        return res.json({ success: false, message: "Invalid request" });
    }

    const timestamp = Date.now();

    db.query(
        "SELECT * FROM followers WHERE userId = ? AND followerId = ?",
        [targetUserId, currentUserId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });
            if (results.length > 0) return res.json({ success: false, message: "Already following" });

            db.query(
                "INSERT INTO follow_requests (senderId, receiverId, timestamp, status) VALUES (?, ?, ?, 'pending')",
                [currentUserId, targetUserId, timestamp],
                async (err) => {
                    if (err) {
                        if (err.code === 'ER_DUP_ENTRY') return res.json({ success: false, message: "Request already sent" });
                        return res.json({ success: false, message: err.message });
                    }

                    // Get sender info
                    db.query("SELECT username, profileImage FROM users WHERE uid = ?", [currentUserId], async (err, userResults) => {
                        if (!err && userResults.length > 0) {
                            const sender = userResults[0];
                            
                            // Send FCM notification
                            await sendFCMNotification(
                                targetUserId,
                                "New Follow Request",
                                `${sender.username} wants to follow you`,
                                {
                                    type: "follow_request",
                                    senderId: currentUserId,
                                    senderUsername: sender.username
                                }
                            );
                            
                            // Create in-app notification
                            createNotification(
                                targetUserId, currentUserId, sender.username,
                                sender.profileImage || "", "sent you a follow request", "follow_request"
                            );
                            
                            // Create pending notification (backup)
                            createPendingNotification(
                                targetUserId, currentUserId, sender.username,
                                "follow_request", "wants to follow you"
                            );
                        }
                    });

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
            if (result.affectedRows === 0) return res.json({ success: false, message: "No pending request found" });

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
            if (results.length === 0) return res.json({ success: false, message: "No pending request found" });

            const timestamp = Date.now();

            db.query("START TRANSACTION", (err) => {
                if (err) return res.json({ success: false, message: err.message });

                db.query("INSERT INTO followers (userId, followerId, timestamp) VALUES (?, ?, ?)", [currentUserId, requesterId, timestamp], (err) => {
                    if (err) { db.query("ROLLBACK"); return res.json({ success: false, message: err.message }); }

                    db.query("UPDATE users SET followersCount = followersCount + 1 WHERE uid = ?", [currentUserId], (err) => {
                        if (err) { db.query("ROLLBACK"); return res.json({ success: false, message: err.message }); }

                        db.query("UPDATE users SET followingCount = followingCount + 1 WHERE uid = ?", [requesterId], (err) => {
                            if (err) { db.query("ROLLBACK"); return res.json({ success: false, message: err.message }); }

                            db.query("UPDATE follow_requests SET status = 'accepted' WHERE senderId = ? AND receiverId = ?", [requesterId, currentUserId], (err) => {
                                if (err) { db.query("ROLLBACK"); return res.json({ success: false, message: err.message }); }

                                db.query("DELETE FROM notifications WHERE userId = ? AND fromUserId = ? AND type = 'follow_request'", [currentUserId, requesterId]);

                                db.query("COMMIT", (err) => {
                                    if (err) { db.query("ROLLBACK"); return res.json({ success: false, message: err.message }); }

                                    console.log(`✅ Follow request accepted: ${requesterId} → ${currentUserId}`);
                                    res.json({ success: true, message: "Request accepted successfully" });
                                });
                            });
                        });
                    });
                });
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
            if (result.affectedRows === 0) return res.json({ success: false, message: "No pending request found" });

            db.query("DELETE FROM notifications WHERE userId = ? AND fromUserId = ? AND type = 'follow_request'", [currentUserId, requesterId]);

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
         FROM follow_requests fr INNER JOIN users u ON fr.senderId = u.uid
         WHERE fr.receiverId = ? AND fr.status = 'pending' ORDER BY fr.timestamp DESC`,
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
         FROM follow_requests fr INNER JOIN users u ON fr.receiverId = u.uid
         WHERE fr.senderId = ? AND fr.status = 'pending' ORDER BY fr.timestamp DESC`,
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
            if (err) return res.json({ success: false, message: err.message });
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
        `SELECT s.*, u.profileImage FROM stories s LEFT JOIN users u ON s.userId = u.uid
         WHERE s.expiryTime > ? ORDER BY s.timestamp DESC`,
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
                    storyId: story.storyId, userId: story.userId, userName: story.userName || story.username,
                    userProfileImage: story.userProfileImage || story.profileImage, imageBase64: story.imageBase64,
                    viewType: story.viewType, timestamp: story.timestamp, expiryTime: story.expiryTime
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
        res.json({ success: true, message: `Deleted ${result.affectedRows} expired stories` });
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

    if (!postId) postId = require('uuid').v4();
    if (!timestamp) timestamp = Date.now();

    db.query(
        `INSERT INTO posts (postId, userId, username, profileImage, images, caption, location, timestamp)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [postId, userId, username || "", profileImage || "", JSON.stringify(images), caption || "", location || "", timestamp],
        (err) => {
            if (err) return res.json({ success: false, message: err.message });
            console.log(`✅ Post uploaded: ${postId} by ${username}`);
            res.json({ success: true, message: "Post uploaded successfully", postId });
        }
    );
});

app.get("/posts/all", (req, res) => {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    db.query(
        `SELECT postId, userId, username, profileImage, images, caption, location, timestamp, likesCount, commentsCount
         FROM posts ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
        [limit, offset],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });

            const posts = results.map(post => ({
                postId: post.postId, userId: post.userId, username: post.username,
                profileImage: post.profileImage || "", images: typeof post.images === 'string' ? JSON.parse(post.images) : post.images,
                caption: post.caption || "", location: post.location || "", timestamp: post.timestamp,
                likesCount: post.likesCount || 0, commentsCount: post.commentsCount || 0
            }));

            res.json({ success: true, posts, limit, offset });
        }
    );
});

app.get("/posts/user/:userId", (req, res) => {
    const { userId } = req.params;

    db.query(
        `SELECT * FROM posts WHERE userId = ? ORDER BY timestamp DESC`,
        [userId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });

            const posts = results.map(post => ({
                postId: post.postId, userId: post.userId, username: post.username,
                profileImage: post.profileImage || "", images: typeof post.images === 'string' ? JSON.parse(post.images) : post.images,
                caption: post.caption || "", location: post.location || "", timestamp: post.timestamp,
                likesCount: post.likesCount || 0, commentsCount: post.commentsCount || 0
            }));

            res.json({ success: true, posts });
        }
    );
});

app.get("/posts/feed/:userId", (req, res) => {
    const { userId } = req.params;
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    db.query(
        `SELECT p.*, EXISTS(SELECT 1 FROM likes WHERE postId = p.postId AND userId = ?) as isLikedByUser
         FROM posts p ORDER BY p.timestamp DESC LIMIT ? OFFSET ?`,
        [userId, limit, offset],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });

            const posts = results.map(post => ({
                postId: post.postId, userId: post.userId, username: post.username,
                profileImage: post.profileImage || "", images: typeof post.images === 'string' ? JSON.parse(post.images) : post.images,
                caption: post.caption || "", location: post.location || "", timestamp: post.timestamp,
                likesCount: post.likesCount || 0, commentsCount: post.commentsCount || 0,
                isLikedByUser: post.isLikedByUser === 1
            }));

            res.json({ success: true, posts, limit, offset });
        }
    );
});

// ======================================================
// COMMENTS & LIKES ENDPOINTS
// ======================================================

app.post("/comments/add", (req, res) => {
    const { commentId, postId, userId, username, profileImage, text, timestamp } = req.body;

    if (!postId || !userId || !username || !text) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    const actualCommentId = commentId || `comment_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const actualTimestamp = timestamp || Date.now();

    db.query("START TRANSACTION", (err) => {
        if (err) return res.json({ success: false, message: err.message });

        db.query(
            `INSERT INTO comments (commentId, postId, userId, username, profileImage, text, timestamp)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [actualCommentId, postId, userId, username, profileImage || "", text, actualTimestamp],
            (err) => {
                if (err) { db.query("ROLLBACK"); return res.json({ success: false, message: err.message }); }

                db.query("UPDATE posts SET commentsCount = commentsCount + 1 WHERE postId = ?", [postId], (err) => {
                    if (err) { db.query("ROLLBACK"); return res.json({ success: false, message: err.message }); }

                    db.query("COMMIT", (err) => {
                        if (err) { db.query("ROLLBACK"); return res.json({ success: false, message: err.message }); }
                        res.json({ success: true, message: "Comment added successfully", commentId: actualCommentId });
                    });
                });
            }
        );
    });
});

app.get("/comments/:postId", (req, res) => {
    const { postId } = req.params;

    db.query("SELECT * FROM comments WHERE postId = ? ORDER BY timestamp ASC", [postId], (err, results) => {
        if (err) return res.json({ success: false, message: err.message });
        res.json({ success: true, comments: results });
    });
});

app.delete("/comments/:commentId", (req, res) => {
    const { commentId } = req.params;
    const { userId } = req.body;

    if (!userId) return res.json({ success: false, message: "Missing user ID" });

    db.query("SELECT * FROM comments WHERE commentId = ? AND userId = ?", [commentId, userId], (err, results) => {
        if (err) return res.json({ success: false, message: err.message });
        if (results.length === 0) return res.json({ success: false, message: "Comment not found or unauthorized" });

        const comment = results[0];

        db.query("START TRANSACTION", (err) => {
            if (err) return res.json({ success: false, message: err.message });

            db.query("DELETE FROM comments WHERE commentId = ?", [commentId], (err) => {
                if (err) { db.query("ROLLBACK"); return res.json({ success: false, message: err.message }); }

                db.query("UPDATE posts SET commentsCount = GREATEST(commentsCount - 1, 0) WHERE postId = ?", [comment.postId], (err) => {
                    if (err) { db.query("ROLLBACK"); return res.json({ success: false, message: err.message }); }

                    db.query("COMMIT", (err) => {
                        if (err) { db.query("ROLLBACK"); return res.json({ success: false, message: err.message }); }
                        res.json({ success: true, message: "Comment deleted successfully" });
                    });
                });
            });
        });
    });
});

app.post("/likes/add", (req, res) => {
    const { postId, userId, username } = req.body;

    if (!postId || !userId || !username) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    const timestamp = Date.now();

    db.query("START TRANSACTION", (err) => {
        if (err) return res.json({ success: false, message: err.message });

        db.query("INSERT INTO likes (postId, userId, username, timestamp) VALUES (?, ?, ?, ?)", [postId, userId, username, timestamp], (err) => {
            if (err) {
                db.query("ROLLBACK");
                if (err.code === 'ER_DUP_ENTRY') return res.json({ success: false, message: "Already liked" });
                return res.json({ success: false, message: err.message });
            }

            db.query("UPDATE posts SET likesCount = likesCount + 1 WHERE postId = ?", [postId], (err) => {
                if (err) { db.query("ROLLBACK"); return res.json({ success: false, message: err.message }); }

                db.query("COMMIT", (err) => {
                    if (err) { db.query("ROLLBACK"); return res.json({ success: false, message: err.message }); }
                    res.json({ success: true, message: "Post liked successfully" });
                });
            });
        });
    });
});

app.delete("/likes/remove", (req, res) => {
    const { postId, userId } = req.body;

    if (!postId || !userId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    db.query("START TRANSACTION", (err) => {
        if (err) return res.json({ success: false, message: err.message });

        db.query("DELETE FROM likes WHERE postId = ? AND userId = ?", [postId, userId], (err, result) => {
            if (err) { db.query("ROLLBACK"); return res.json({ success: false, message: err.message }); }
            if (result.affectedRows === 0) { db.query("ROLLBACK"); return res.json({ success: false, message: "Like not found" }); }

            db.query("UPDATE posts SET likesCount = GREATEST(likesCount - 1, 0) WHERE postId = ?", [postId], (err) => {
                if (err) { db.query("ROLLBACK"); return res.json({ success: false, message: err.message }); }

                db.query("COMMIT", (err) => {
                    if (err) { db.query("ROLLBACK"); return res.json({ success: false, message: err.message }); }
                    res.json({ success: true, message: "Post unliked successfully" });
                });
            });
        });
    });
});

app.get("/likes/check/:postId/:userId", (req, res) => {
    const { postId, userId } = req.params;

    db.query("SELECT * FROM likes WHERE postId = ? AND userId = ?", [postId, userId], (err, results) => {
        if (err) return res.json({ success: false, message: err.message });
        res.json({ success: true, isLiked: results.length > 0 });
    });
});

app.get("/likes/:postId", (req, res) => {
    const { postId } = req.params;

    db.query(
        `SELECT l.userId, l.username, l.timestamp, u.profileImage, u.name
         FROM likes l LEFT JOIN users u ON l.userId = u.uid
         WHERE l.postId = ? ORDER BY l.timestamp DESC`,
        [postId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, likes: results });
        }
    );
});

// ======================================================
// NOTIFICATION ENDPOINTS (Your existing ones)
// ======================================================

app.get("/notifications/:userId", (req, res) => {
    const { userId } = req.params;
    const includeRead = req.query.includeRead === 'true';

    let notificationsQuery = `SELECT id as notificationId, userId, fromUserId, fromUsername, fromProfileImage,
        message, type, postImage, timestamp, isRead FROM notifications WHERE userId = ?`;
   
    if (!includeRead) notificationsQuery += ` AND isRead = FALSE`;

    const followRequestsQuery = `SELECT fr.id as notificationId, fr.receiverId as userId, fr.senderId as fromUserId,
        u.username as fromUsername, u.profileImage as fromProfileImage, 'sent you a follow request' as message,
        'follow_request' as type, NULL as postImage, fr.timestamp, FALSE as isRead
        FROM follow_requests fr INNER JOIN users u ON fr.senderId = u.uid
        WHERE fr.receiverId = ? AND fr.status = 'pending'`;

    db.query(notificationsQuery, [userId], (err, notificationResults) => {
        if (err) return res.json({ success: false, message: err.message });

        db.query(followRequestsQuery, [userId], (err, followRequestResults) => {
            if (err) return res.json({ success: false, message: err.message });

            const allNotifications = [...notificationResults, ...followRequestResults];
            allNotifications.sort((a, b) => b.timestamp - a.timestamp);
            const limitedNotifications = allNotifications.slice(0, 50);

            res.json({ success: true, notifications: limitedNotifications, count: limitedNotifications.length });
        });
    });
});

app.post("/notifications/markRead", (req, res) => {
    const { notificationId } = req.body;

    if (!notificationId) return res.json({ success: false, message: "Missing notification ID" });

    db.query("UPDATE notifications SET isRead = TRUE WHERE id = ?", [notificationId], (err) => {
        if (err) return res.json({ success: false, message: err.message });
        res.json({ success: true, message: "Notification marked as read" });
    });
});

app.post("/notifications/markAllRead", (req, res) => {
    const { userId } = req.body;

    if (!userId) return res.json({ success: false, message: "Missing user ID" });

    db.query("UPDATE notifications SET isRead = TRUE WHERE userId = ? AND isRead = FALSE", [userId], (err, result) => {
        if (err) return res.json({ success: false, message: err.message });
        res.json({ success: true, message: `Marked ${result.affectedRows} notifications as read` });
    });
});

app.delete("/notifications/:notificationId", (req, res) => {
    const { notificationId } = req.params;

    db.query("DELETE FROM notifications WHERE id = ?", [notificationId], (err) => {
        if (err) return res.json({ success: false, message: err.message });
        res.json({ success: true, message: "Notification deleted" });
    });
});

// ======================================================
// NEW: PENDING NOTIFICATIONS FOR POLLING
// ======================================================

app.get("/notifications/pending/:userId", (req, res) => {
    const { userId } = req.params;

    db.query(
        `SELECT * FROM pending_notifications WHERE user_id = ? AND delivered = FALSE
         ORDER BY timestamp DESC LIMIT 20`,
        [userId],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });

            console.log(`📬 Found ${results.length} pending notifications for ${userId}`);
            res.json({ success: true, notifications: results });
        }
    );
});

app.post("/notifications/markDelivered", (req, res) => {
    const { notificationId } = req.body;

    if (!notificationId) return res.json({ success: false, message: "Missing notification ID" });

    db.query("UPDATE pending_notifications SET delivered = TRUE WHERE notification_id = ?", [notificationId], (err) => {
        if (err) return res.json({ success: false, message: err.message });
        res.json({ success: true, message: "Notification marked as delivered" });
    });
});

app.delete("/notifications/cleanup", (req, res) => {
    const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);

    db.query("DELETE FROM pending_notifications WHERE delivered = TRUE AND timestamp < ?", [oneDayAgo], (err, result) => {
        if (err) return res.json({ success: false, message: err.message });
        res.json({ success: true, message: `Deleted ${result.affectedRows} old notifications` });
    });
});

// ======================================================
// MESSAGING ENDPOINTS
// ======================================================

app.post("/messages/send", async (req, res) => {
    const { messageId, senderId, receiverUid, messageText, imageData, timestamp, isSystemMessage } = req.body;

    if (!senderId || !receiverUid) {
        return res.json({ success: false, message: "Missing required fields: senderId and receiverUid" });
    }

    if (!messageText && !imageData) {
        return res.json({ success: false, message: "Missing message content" });
    }

    const chatId = senderId < receiverUid ? `${senderId}_${receiverUid}` : `${receiverUid}_${senderId}`;
    const actualTimestamp = timestamp || Date.now();

    db.query(
        `INSERT INTO messages (messageId, senderId, receiverId, chatId, messageText, imageData, timestamp, isSystemMessage, isVanishMode)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, FALSE)`,
        [messageId || `msg_${Date.now()}`, senderId, receiverUid, chatId, messageText || null, imageData || null, actualTimestamp, isSystemMessage || false],
        async (err) => {
            if (err) return res.json({ success: false, message: "Database error: " + err.message });

            // Get sender's username
            db.query("SELECT username, profileImage FROM users WHERE uid = ?", [senderId], async (err, results) => {
                if (!err && results.length > 0) {
                    const senderUsername = results[0].username;
                    const senderProfileImage = results[0].profileImage || "";
                    
                    // Prepare notification
                    let notificationTitle = senderUsername;
                    let notificationBody = "";
                    
                    if (imageData) {
                        notificationBody = "📷 Sent a photo";
                    } else {
                        notificationBody = messageText.length > 100 ? 
                            messageText.substring(0, 100) + "..." : 
                            messageText;
                    }

                    // Send FCM notification
                    await sendFCMNotification(
                        receiverUid,
                        notificationTitle,
                        notificationBody,
                        {
                            type: "message",
                            senderId: senderId,
                            senderUsername: senderUsername,
                            chatId: chatId,
                            messageId: messageId || `msg_${Date.now()}`
                        }
                    );

                    // Create pending notification for polling (backup)
                    createPendingNotification(receiverUid, senderId, senderUsername, "message", notificationBody);
                }
            });

            res.json({ 
                success: true, 
                message: "Message sent successfully", 
                messageId: messageId || `msg_${Date.now()}`, 
                chatId 
            });
        }
    );
});

app.put("/messages/edit", (req, res) => {
    const { messageId, newText, senderId } = req.body;

    if (!messageId || !newText || !senderId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    db.query("SELECT * FROM messages WHERE messageId = ? AND senderId = ?", [messageId, senderId], (err, results) => {
        if (err) return res.json({ success: false, message: err.message });
        if (results.length === 0) return res.json({ success: false, message: "Message not found" });

        const message = results[0];
        const fifteenMinutes = 15 * 60 * 1000;

        if (Date.now() - message.timestamp > fifteenMinutes) {
            return res.json({ success: false, message: "Can't edit message after 15 minutes" });
        }

        db.query("UPDATE messages SET messageText = ?, isEdited = TRUE WHERE messageId = ?", [newText, messageId], (err) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, message: "Message edited successfully" });
        });
    });
});

app.delete("/messages/delete", (req, res) => {
    const { messageId, senderId } = req.body;

    if (!messageId || !senderId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    db.query("SELECT * FROM messages WHERE messageId = ? AND senderId = ?", [messageId, senderId], (err, results) => {
        if (err) return res.json({ success: false, message: err.message });
        if (results.length === 0) return res.json({ success: false, message: "Message not found" });

        const message = results[0];
        const fifteenMinutes = 15 * 60 * 1000;

        if (Date.now() - message.timestamp > fifteenMinutes) {
            return res.json({ success: false, message: "Can't delete message after 15 minutes" });
        }

        db.query("DELETE FROM messages WHERE messageId = ?", [messageId], (err) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, message: "Message deleted successfully" });
        });
    });
});

app.get("/messages/:chatId", (req, res) => {
    const { chatId } = req.params;

    db.query("SELECT * FROM messages WHERE chatId = ? ORDER BY timestamp ASC", [chatId], (err, results) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, messages: results });
    });
});

app.post("/conversations/update", (req, res) => {
    const { userId, otherUserId, otherUsername, otherUserImage, lastMessage, timestamp } = req.body;

    if (!userId || !otherUserId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    const actualTimestamp = timestamp || Date.now();

    db.query(
        `INSERT INTO conversations (userId, otherUserId, otherUsername, otherUserImage, lastMessage, timestamp, unreadCount)
         VALUES (?, ?, ?, ?, ?, ?, 0) ON DUPLICATE KEY UPDATE
         otherUsername = VALUES(otherUsername), otherUserImage = VALUES(otherUserImage),
         lastMessage = VALUES(lastMessage), timestamp = VALUES(timestamp)`,
        [userId, otherUserId, otherUsername, otherUserImage || "", lastMessage, actualTimestamp],
        (err) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, message: "Conversation updated" });
        }
    );
});

app.get("/conversations/:userId", (req, res) => {
    const { userId } = req.params;

    db.query("SELECT * FROM conversations WHERE userId = ? ORDER BY timestamp DESC", [userId], (err, results) => {
        if (err) return res.json({ success: false, message: err.message });
        res.json({ success: true, conversations: results });
    });
});

app.post("/messages/markSeen", (req, res) => {
    const { chatId, userId } = req.body;

    if (!chatId || !userId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    const seenAt = Date.now();

    db.query(
        `UPDATE messages SET seenAt = ?, isVanishMode = TRUE
         WHERE chatId = ? AND receiverId = ? AND seenAt IS NULL`,
        [seenAt, chatId, userId],
        (err, result) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, message: "Messages marked as seen", count: result.affectedRows });
        }
    );
});

app.delete("/messages/deleteVanished", (req, res) => {
    const { chatId, userId } = req.body;

    if (!chatId || !userId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    db.query(
        `DELETE FROM messages WHERE chatId = ? AND receiverId = ? AND isVanishMode = TRUE AND seenAt IS NOT NULL`,
        [chatId, userId],
        (err, result) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, message: "Vanished messages deleted", count: result.affectedRows });
        }
    );
});

app.get("/users/search/:query", (req, res) => {
    const { query } = req.params;

    if (!query || query.length < 2) {
        return res.json({ success: false, message: "Query too short" });
    }

    db.query(
        `SELECT uid, username, email, name, lastname, profileImage, profilePicture
         FROM users WHERE username LIKE ? OR name LIKE ? LIMIT 20`,
        [`${query}%`, `${query}%`],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });

            const users = results.map(user => ({
                uid: user.uid, username: user.username, email: user.email, name: user.name,
                lastname: user.lastname || "", profileImage: user.profileImage || user.profilePicture || "", bio: ""
            }));

            res.json({ success: true, users });
        }
    );
});

// ======================================================
// SCREENSHOT ENDPOINTS
// ======================================================

app.post("/screenshots/record", async (req, res) => {
    const { chatId, userId, username, timestamp } = req.body;

    if (!chatId || !userId || !username) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    const actualTimestamp = timestamp || Date.now();

    db.query(
        `INSERT INTO screenshot_events (chatId, userId, username, timestamp) VALUES (?, ?, ?, ?)`,
        [chatId, userId, username, actualTimestamp],
        async (err) => {
            if (err) return res.json({ success: false, message: err.message });

            const messageId = `msg_screenshot_${Date.now()}`;
            
            // Create system message
            db.query(
                `INSERT INTO messages (messageId, senderId, receiverId, chatId, messageText, timestamp, isSystemMessage, isVanishMode)
                 VALUES (?, ?, ?, ?, ?, ?, TRUE, FALSE)`,
                [messageId, userId, userId, chatId, `${username} took a screenshot`, actualTimestamp],
                (err) => {
                    if (err) console.error("Error creating system message:", err);
                }
            );

            // Get the other user ID from chatId
            const parts = chatId.split('_');
            const otherUserId = parts[0] === userId ? parts[1] : parts[0];
            
            // Send FCM notification about screenshot
            await sendFCMNotification(
                otherUserId,
                "Screenshot Alert! 📸",
                `${username} took a screenshot of your chat`,
                {
                    type: "screenshot",
                    senderId: userId,
                    senderUsername: username,
                    chatId: chatId
                }
            );

            // Create pending notification (backup)
            createPendingNotification(otherUserId, userId, username, "screenshot", "took a screenshot of your chat");

            res.json({ success: true, message: "Screenshot recorded", messageId });
        }
    );
});

app.get("/screenshots/:chatId", (req, res) => {
    const { chatId } = req.params;
    const limit = parseInt(req.query.limit) || 50;

    db.query(
        `SELECT * FROM screenshot_events WHERE chatId = ? ORDER BY timestamp DESC LIMIT ?`,
        [chatId, limit],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, screenshots: results });
        }
    );
});

app.get("/screenshots/user/:userId", (req, res) => {
    const { userId } = req.params;
    const limit = parseInt(req.query.limit) || 20;

    db.query(
        `SELECT * FROM screenshot_events WHERE userId = ? ORDER BY timestamp DESC LIMIT ?`,
        [userId, limit],
        (err, results) => {
            if (err) return res.json({ success: false, message: err.message });
            res.json({ success: true, screenshots: results });
        }
    );
});

app.delete("/screenshots/cleanup", (req, res) => {
    const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);

    db.query("DELETE FROM screenshot_events WHERE timestamp < ?", [thirtyDaysAgo], (err, result) => {
        if (err) return res.json({ success: false, message: err.message });
        res.json({ success: true, message: `Deleted ${result.affectedRows} old screenshots` });
    });
});

// ======================================================
// CALL ENDPOINTS
// ======================================================
// ======================================================
// PRESENCE ENDPOINTS - FIXED VERSION
// ======================================================

app.post("/users/presence/update", (req, res) => {
    const { userId, isOnline } = req.body;

    if (!userId) {
        return res.status(400).json({ success: false, message: "Missing user ID" });
    }

    const lastSeen = Date.now();

    console.log(`👤 Updating presence for ${userId}: ${isOnline ? 'online' : 'offline'} at ${new Date(lastSeen).toISOString()}`);

    db.query(
        `INSERT INTO user_presence (user_id, is_online, last_seen) VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE is_online = VALUES(is_online), last_seen = VALUES(last_seen)`,
        [userId, isOnline ? 1 : 0, lastSeen],
        (err) => {
            if (err) {
                console.log("❌ Error updating presence:", err);
                return res.status(500).json({ success: false, message: err.message });
            }
           
            console.log(`✅ Presence updated for ${userId}`);
            res.json({ success: true, message: "Presence updated" });
        }
    );
});

app.get("/users/presence/:userId", (req, res) => {
    const { userId } = req.params;

    console.log(`🔍 Checking presence for ${userId}`);

    db.query("SELECT is_online, last_seen FROM user_presence WHERE user_id = ?", [userId], (err, results) => {
        if (err) {
            console.log("❌ Database error:", err);
            return res.status(500).json({ success: false, message: err.message });
        }
       
        if (results.length === 0) {
            console.log(`⚠️ No presence record found for ${userId} - treating as offline`);
            return res.json({ success: true, isOnline: false, lastSeen: 0 });
        }

        const presence = results[0];
        const thirtySecondsAgo = Date.now() - 30000;
        const isOnline = presence.is_online && presence.last_seen > thirtySecondsAgo;

        console.log(`📊 User ${userId} presence:`, {
            is_online: presence.is_online,
            last_seen: new Date(presence.last_seen).toISOString(),
            calculated_online: isOnline,
            time_diff_ms: Date.now() - presence.last_seen
        });

        res.json({
            success: true,
            isOnline,
            lastSeen: presence.last_seen
        });
    });
});

// ======================================================
// CALL ENDPOINTS - FIXED VERSION
// ======================================================

app.post("/call/initiate", (req, res) => {
    const { caller_id, caller_name, caller_profile_image, receiver_id, channel_name, call_type } = req.body;

    console.log("📞 Call initiation request:", { caller_id, caller_name, receiver_id, call_type });

    if (!caller_id || !receiver_id || !channel_name || !call_type) {
        console.log("❌ Missing required fields");
        return res.status(400).json({ success: false, message: "Missing required fields" });
    }

    if (caller_id === receiver_id) {
        console.log("❌ Cannot call yourself");
        return res.status(400).json({ success: false, message: "Cannot call yourself" });
    }

    // Check if receiver is online
    db.query("SELECT is_online, last_seen FROM user_presence WHERE user_id = ?", [receiver_id], (err, results) => {
        if (err) {
            console.log("❌ Database error:", err);
            return res.status(500).json({ success: false, message: "Database error" });
        }

        // Check if user is online (updated within last 30 seconds)
        const thirtySecondsAgo = Date.now() - 30000;
        const isOnline = results.length > 0 && results[0].is_online && results[0].last_seen > thirtySecondsAgo;
       
        console.log("🔍 Receiver presence check:", {
            receiver_id,
            has_record: results.length > 0,
            is_online_flag: results.length > 0 ? results[0].is_online : false,
            last_seen: results.length > 0 ? new Date(results[0].last_seen).toISOString() : 'never',
            time_diff_ms: results.length > 0 ? Date.now() - results[0].last_seen : 'N/A',
            calculated_online: isOnline
        });

        if (!isOnline) {
            console.log("❌ User is offline");
            return res.status(400).json({ success: false, message: "User is offline" });
        }

        const call_id = `call_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const timestamp = Date.now();

        // Insert call request
        db.query(
            `INSERT INTO call_requests (call_id, caller_id, caller_name, caller_profile_image, receiver_id, channel_name, call_type, status, timestamp)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'calling', ?)`,
            [call_id, caller_id, caller_name, caller_profile_image || "", receiver_id, channel_name, call_type, timestamp],
            (err) => {
                if (err) {
                    console.log("❌ Failed to create call request:", err);
                    return res.status(500).json({ success: false, message: "Failed to create call request" });
                }

                console.log(`✅ Call request created: ${call_id} (${caller_name} → ${receiver_id})`);
               
                // Return success immediately
                res.json({
                    success: true,
                    message: "Call request created",
                    call_id,
                    channel_name
                });

                // Create notification asynchronously (don't wait for it)
                if (typeof createPendingNotification === 'function') {
                    createPendingNotification(
                        receiver_id,
                        caller_id,
                        caller_name,
                        "incoming_call",
                        `Incoming ${call_type} call`,
                        {
                            callId: call_id,
                            channelName: channel_name,
                            callType: call_type,
                            callerProfileImage: caller_profile_image || ""
                        }
                    );
                }
            }
        );
    });
});

app.get("/call/incoming/:userId", (req, res) => {
    const { userId } = req.params;

    console.log(`🔍 Checking incoming calls for user: ${userId}`);

    db.query(
        `SELECT * FROM call_requests
         WHERE receiver_id = ? AND status = 'calling'
         ORDER BY timestamp DESC LIMIT 10`,
        [userId],
        (err, results) => {
            if (err) {
                console.log("❌ Error fetching calls:", err);
                return res.status(500).json({ success: false, message: err.message });
            }
           
            console.log(`📋 Found ${results.length} pending call(s) for ${userId}`);
            res.json(results);
        }
    );
});

app.get("/call/:callId/status", (req, res) => {
    const { callId } = req.params;

    db.query("SELECT status FROM call_requests WHERE call_id = ?", [callId], (err, results) => {
        if (err) {
            console.log("❌ Error fetching call status:", err);
            return res.status(500).json({ success: false, message: err.message });
        }
        if (results.length === 0) {
            console.log("❌ Call not found:", callId);
            return res.status(404).json({ success: false, message: "Call not found" });
        }
       
        const status = results[0].status;
        console.log(`📊 Call ${callId} status: ${status}`);
        res.json({ success: true, status });
    });
});

app.put("/call/:callId/status", (req, res) => {
    const { callId } = req.params;
    const { status } = req.body;

    console.log(`🔄 Updating call ${callId} to status: ${status}`);

    if (!status || !['calling', 'accepted', 'rejected', 'ended'].includes(status)) {
        console.log("❌ Invalid status");
        return res.status(400).json({ success: false, message: "Invalid status" });
    }

    db.query("UPDATE call_requests SET status = ? WHERE call_id = ?", [status, callId], (err, result) => {
        if (err) {
            console.log("❌ Error updating status:", err);
            return res.status(500).json({ success: false, message: err.message });
        }
        if (result.affectedRows === 0) {
            console.log("❌ Call not found");
            return res.status(404).json({ success: false, message: "Call not found" });
        }
       
        console.log(`✅ Call status updated: ${callId} → ${status}`);
        res.json({ success: true, message: "Status updated" });
    });
});

app.delete("/call/:callId", (req, res) => {
    const { callId } = req.params;

    console.log(`🗑️ Deleting call: ${callId}`);

    db.query("DELETE FROM call_requests WHERE call_id = ?", [callId], (err) => {
        if (err) {
            console.log("❌ Error deleting call:", err);
            return res.status(500).json({ success: false, message: err.message });
        }
       
        console.log(`✅ Call deleted: ${callId}`);
        res.json({ success: true, message: "Call request deleted" });
    });
});

app.delete("/call/cleanup", (req, res) => {
    const twoMinutesAgo = Date.now() - (2 * 60 * 1000);

    console.log("🧹 Cleaning up old calls...");

    db.query("DELETE FROM call_requests WHERE timestamp < ? AND status = 'calling'", [twoMinutesAgo], (err, result) => {
        if (err) {
            console.log("❌ Error cleaning up calls:", err);
            return res.status(500).json({ success: false, message: err.message });
        }
       
        console.log(`✅ Deleted ${result.affectedRows} expired calls`);
        res.json({ success: true, message: `Deleted ${result.affectedRows} expired calls` });
    });
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
            console.log(`✅ FCM token updated for user: ${userId}`);
            res.json({ success: true, message: "FCM token updated" });
        }
    );
});


// Test endpoint to send notification
app.post("/test/notification", async (req, res) => {
    const { userId, title, body } = req.body;
    
    const success = await sendFCMNotification(userId, title, body, { type: "test" });
    
    res.json({ 
        success, 
        message: success ? "Notification sent" : "Failed to send notification" 
    });
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
    console.log(`✅ All endpoints ready`);
    console.log(`📬 Notification polling system enabled`);
    console.log(`📞 Call system enabled`);
});