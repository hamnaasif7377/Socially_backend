require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

// Database pool
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

// --- Step 1: Create dummy table if it doesn't exist ---
db.query(`
CREATE TABLE IF NOT EXISTS test_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    uid VARCHAR(255) UNIQUE,
    username VARCHAR(255),
    email VARCHAR(255) UNIQUE,
    password VARCHAR(255),
    name VARCHAR(255)
)
`, (err) => {
    if (err) console.error("Error creating table:", err);
    else {
        console.log("Dummy table ready.");

        // Insert dummy user if table is empty
        db.query("SELECT * FROM test_users LIMIT 1", (err, results) => {
            if (results.length === 0) {
                const dummyPassword = bcrypt.hashSync("123456", 10);
                db.query(
                    "INSERT INTO test_users (uid, username, email, password, name) VALUES (?, ?, ?, ?, ?)",
                    ['t1', 'dummyuser', 'dummy@example.com', dummyPassword, 'Dummy'],
                    (err) => {
                        if (err) console.error("Error inserting dummy user:", err);
                        else console.log("Dummy user inserted.");
                    }
                );
            }
        });
    }
});

// --- Step 2: Test route ---
app.get("/", (req, res) => {
    res.send("Server is running!");
});

// --- Step 3: Login endpoint ---
app.post("/login", (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.json({ success: false, message: "Email and password required" });

    db.query("SELECT * FROM test_users WHERE email = ?", [email], (err, results) => {
        if (err) return res.json({ success: false, message: err.message });
        if (results.length === 0) return res.json({ success: false, message: "User not found" });

        const user = results[0];
        if (bcrypt.compareSync(password, user.password)) {
            delete user.password; // remove password from response
            res.json({ success: true, user });
        } else {
            res.json({ success: false, message: "Invalid password" });
        }
    });
});

// --- Step 4: Start server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

module.exports = { db };
