const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const DB_PATH = path.join(__dirname, "users.db");
console.log("Database path:", DB_PATH);

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error("Error connecting to database:", err);
    process.exit(1);
  }
  console.log("Connected to database");
});

// First, let's check the table structure
db.all("PRAGMA table_info(users)", [], (err, columns) => {
  if (err) {
    console.error("Error getting table info:", err);
  } else {
    console.log("\nUsers table structure:");
    console.log(columns);
  }

  // Now let's check the actual data
  db.all("SELECT * FROM users", [], (err, rows) => {
    if (err) {
      console.error("Error querying users:", err);
    } else {
      console.log("\nUsers in database:");
      console.log(rows);
    }

    // Close the database connection
    db.close((err) => {
      if (err) {
        console.error("Error closing database:", err);
      }
      console.log("Database connection closed");
    });
  });
});
