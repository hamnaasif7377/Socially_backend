<?php
include 'db.php';

// SQL to create dummy table if it doesn't exist
$sql = "CREATE TABLE IF NOT EXISTS test_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    uid VARCHAR(255) UNIQUE,
    username VARCHAR(255),
    email VARCHAR(255) UNIQUE,
    password VARCHAR(255),
    name VARCHAR(255)
)";

if ($conn->query($sql) === TRUE) {
    echo "Dummy table created successfully.<br>";
} else {
    echo "Error creating table: " . $conn->error . "<br>";
}

// Insert a dummy user if table is empty
$check = $conn->query("SELECT * FROM test_users LIMIT 1");
if ($check->num_rows === 0) {
    $dummyPassword = password_hash("123456", PASSWORD_DEFAULT);
    $conn->query("INSERT INTO test_users (uid, username, email, password, name) 
                  VALUES ('t1', 'dummyuser', 'dummy@example.com', '$dummyPassword', 'Dummy')");
    echo "Dummy user inserted successfully.";
} else {
    echo "Table already has data, skipping dummy user.";
}

$conn->close();
?>
