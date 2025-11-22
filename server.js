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

// ======================================================
// ---------- STORY ENDPOINTS
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

// ======================================================
// ---------- POST ENDPOINTS
// ======================================================

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
    commentsCount INT DEFAULT 0
)`;

db.query(createPostsTable, (err, result) => {
    if (err) console.error("Error creating posts table:", err);
    else console.log("✅ Posts table ready");
});

// Ensure index exists on timestamp for sorting
const createIndexQuery = `
    ALTER TABLE posts
    ADD INDEX idx_posts_timestamp (timestamp DESC)
`;

db.query(createIndexQuery, (err) => {
    if (err) {
        if (err.code === 'ER_DUP_KEYNAME') {
            console.log("✅ Index idx_posts_timestamp already exists");
        } else {
            console.error("❌ Error creating index:", err);
        }
    } else {
        console.log("✅ Index idx_posts_timestamp created");
    }
});


// POST - Upload a post
app.post("/posts/upload", (req, res) => {
    let { postId, userId, username, profileImage, images, caption, location, timestamp } = req.body;

    if (!userId || !images || images.length === 0) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    if (!postId) {
        postId = require('uuid').v4(); // generate unique ID
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

// GET - Retrieve all posts with pagination
app.get("/posts/all", (req, res) => {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    // Only select necessary columns
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


// GET - Retrieve posts by specific user
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

// Add these endpoints to your existing server.js file

// ======================================================
// ---------- FOLLOWERS/FOLLOWING ENDPOINTS
// ======================================================

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

// Follow a user
app.post("/users/follow", (req, res) => {
    const { currentUserId, targetUserId } = req.body;

    if (!currentUserId || !targetUserId) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    if (currentUserId === targetUserId) {
        return res.json({ success: false, message: "Cannot follow yourself" });
    }

    const timestamp = Date.now();

    // Insert follow relationship
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

            // Update follower/following counts
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

// Unfollow a user
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

            // Update follower/following counts
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

// Check if following
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

// ======================================================
// ---------- USER SEARCH ENDPOINT
// ======================================================

app.post("/users/search", (req, res) => {
    const { currentUserId, query, filter } = req.body;

    console.log(`🔍 Search request - User: ${currentUserId}, Query: "${query}", Filter: ${filter}`);

    if (!currentUserId || !query) {
        return res.json({ success: false, message: "Missing required fields" });
    }

    // Sanitize query for SQL LIKE pattern
    const searchPattern = `${query.toLowerCase()}%`;

    let sqlQuery;
    let queryParams;

    switch (filter) {
        case "Followers":
            // Search users who follow the current user
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
            // Search users that current user follows
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
            // Search all users except current user
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

// Get followers list
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

// Get following list
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

// GLOBAL ERROR HANDLING
process.on('uncaughtException', err => console.error('Uncaught Exception:', err));
process.on('unhandledRejection', err => console.error('Unhandled Rejection:', err));

app.listen(process.env.PORT || 3000, () => {
    console.log(`🚀 Server running on port ${process.env.PORT || 3000}`);
});