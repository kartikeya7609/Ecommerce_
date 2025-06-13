const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const path = require("path");

const DB_PATH = path.join(__dirname, "users.db");
const SALT_ROUNDS = 10;

// Initialize database connection
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error("❌ Failed to connect to the database:", err.message);
    process.exit(1);
  } else {
    console.log("✅ Connected to SQLite database.");
    initializeDatabase();
  }
});

// Handle database process termination
process.on("SIGINT", () => {
  db.close((err) => {
    if (err) {
      console.error("❌ Failed to close database:", err.message);
    } else {
      console.log("✅ Database connection closed.");
    }
    process.exit(0);
  });
});

// Initialize database tables
function initializeDatabase() {
  db.serialize(() => {
    // Users table with indexes
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        username TEXT,
        bio TEXT,
        location TEXT,
        website TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,
      (err) => {
        if (err) {
          console.error("❌ Failed to create users table:", err.message);
        } else {
          console.log("✅ Users table is ready.");
          // Create index for faster email lookups
          db.run("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)");
        }
      }
    );

    // Contacts table
    db.run(
      `CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,
      (err) => {
        if (err) {
          console.error("❌ Failed to create contacts table:", err.message);
        } else {
          console.log("✅ Contacts table is ready.");
        }
      }
    );

    // Cart table
    db.run(
      `CREATE TABLE IF NOT EXISTS carts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        email TEXT NOT NULL,
        title TEXT NOT NULL,
        price REAL NOT NULL,
        image TEXT,
        quantity INTEGER NOT NULL DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, product_id)
      )`,
      (err) => {
        if (err) {
          console.error("❌ Failed to create carts table:", err.message);
        } else {
          console.log("✅ Carts table is ready.");
          // Create indexes for faster lookups
          db.run(
            "CREATE INDEX IF NOT EXISTS idx_carts_user_id ON carts(user_id)"
          );
          db.run(
            "CREATE INDEX IF NOT EXISTS idx_carts_product_id ON carts(product_id)"
          );
        }
      }
    );
  });
}

/**
 * User Management Functions
 */

function registerUser(name, email, plainPassword, callback) {
  if (typeof callback !== "function") {
    throw new Error("Callback function is required");
  }

  if (!name || !email || !plainPassword) {
    console.log("Missing required fields in registerUser");
    return callback(new Error("Name, email, and password are required"));
  }

  if (
    typeof name !== "string" ||
    typeof email !== "string" ||
    typeof plainPassword !== "string"
  ) {
    console.log("Invalid input types in registerUser");
    return callback(new Error("Invalid input types"));
  }

  const trimmedName = name.trim();
  const trimmedEmail = email.trim();

  if (!trimmedName || !trimmedEmail || !plainPassword.trim()) {
    console.log("Empty fields after trimming in registerUser");
    return callback(new Error("Name, email, and password cannot be empty"));
  }

  console.log("Starting user registration for:", trimmedEmail);

  bcrypt.hash(plainPassword, SALT_ROUNDS, (err, hash) => {
    if (err) {
      console.error("Error hashing password:", err);
      return callback(err);
    }

    console.log("Password hashed successfully");

    const query = `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`;
    db.run(query, [trimmedName, trimmedEmail, hash], function (err) {
      if (err) {
        console.error("Database error during registration:", err);
        if (err.message.includes("UNIQUE constraint failed")) {
          return callback(new Error("Email already exists"));
        }
        return callback(err);
      }
      console.log("User registered successfully with ID:", this.lastID);
      callback(null, this.lastID);
    });
  });
}

function authenticateUser(email, plainPassword, callback) {
  if (typeof callback !== "function") {
    throw new Error("Callback function is required");
  }

  if (!email || !plainPassword) {
    return callback(new Error("Email and password are required"));
  }

  const trimmedEmail = email.trim();
  console.log("Attempting to authenticate user with email:", trimmedEmail);

  const query = `SELECT * FROM users WHERE email = ?`;
  db.get(query, [trimmedEmail], (err, user) => {
    if (err) {
      console.error("Database error during authentication:", err);
      return callback(err);
    }
    if (!user) {
      console.log("No user found with email:", trimmedEmail);
      return callback(null, null); // User not found
    }

    console.log("User found, comparing passwords...");
    bcrypt.compare(plainPassword, user.password, (err, match) => {
      if (err) {
        console.error("Password comparison error:", err);
        return callback(err);
      }
      if (!match) {
        console.log("Password mismatch for user:", trimmedEmail);
        return callback(null, null); // Password mismatch
      }

      console.log("Authentication successful for user:", trimmedEmail);
      // Return user data without password
      const userData = { ...user };
      delete userData.password; // Remove password from the returned data
      console.log("User data being returned:", userData);
      callback(null, userData);
    });
  });
}

function updateUserProfile(userId, profileData, callback) {
  if (typeof callback !== "function") {
    throw new Error("Callback function is required");
  }

  if (!userId || typeof userId !== "number" || userId <= 0) {
    return callback(new Error("Valid user ID is required"));
  }

  if (!profileData || typeof profileData !== "object") {
    return callback(new Error("Profile data is required"));
  }

  // Prepare update fields
  const updates = {
    name: profileData.name?.trim() || "",
    username: profileData.username?.trim() || "",
    bio: profileData.bio?.trim() || "",
    location: profileData.location?.trim() || "",
    website: profileData.website?.trim() || "",
  };

  const query = `
    UPDATE users
    SET name = ?, username = ?, bio = ?, location = ?, website = ?
    WHERE id = ?`;

  db.run(
    query,
    [
      updates.name,
      updates.username,
      updates.bio,
      updates.location,
      updates.website,
      userId,
    ],
    function (err) {
      if (err) return callback(err);
      callback(null, this.changes > 0);
    }
  );
}

function getUserById(userId, callback) {
  if (typeof callback !== "function") {
    throw new Error("Callback function is required");
  }

  // Convert userId to number if it's a string
  const id = typeof userId === "string" ? parseInt(userId, 10) : userId;

  if (!id || isNaN(id) || id <= 0) {
    console.error("Invalid user ID provided:", userId);
    return callback(new Error("Valid user ID is required"));
  }

  console.log("Fetching user with ID:", id);

  // First, let's check if the database is properly connected
  if (!db) {
    console.error("Database connection is not initialized");
    return callback(new Error("Database connection error"));
  }

  // Let's try a simpler query first to verify the database is working
  const testQuery = "SELECT 1 as test";
  db.get(testQuery, [], (err, result) => {
    if (err) {
      console.error("Database connection test failed:", err);
      return callback(new Error("Database connection test failed"));
    }
    console.log("Database connection test successful");

    // Now proceed with the actual query
    const query = "SELECT id, name, email FROM users WHERE id = ?";
    console.log("Executing query:", query, "with params:", [id]);

    db.get(query, [id], (err, row) => {
      if (err) {
        console.error("Database error in getUserById:", err);
        return callback(err);
      }

      if (!row) {
        console.log("No user found with ID:", id);
        return callback(null, null);
      }

      console.log("User found:", row);
      callback(null, row);
    });
  });
}

function getUserByEmail(email, callback) {
  if (typeof callback !== "function") {
    throw new Error("Callback function is required");
  }

  if (!email || typeof email !== "string") {
    return callback(new Error("Valid email is required"));
  }

  const trimmedEmail = email.trim();
  if (!trimmedEmail) {
    return callback(new Error("Email cannot be empty"));
  }

  const query = `
    SELECT * 
    FROM users 
    WHERE email = ?`;

  db.get(query, [trimmedEmail], (err, row) => {
    if (err) return callback(err);
    callback(null, row || null);
  });
}

/**
 * Contact Management Functions
 */

function saveContact(name, email, message, callback) {
  if (typeof callback !== "function") {
    throw new Error("Callback function is required");
  }

  if (!name || !email || !message) {
    return callback(new Error("Name, email, and message are required"));
  }

  const trimmedName = name.trim();
  const trimmedEmail = email.trim();
  const trimmedMessage = message.trim();

  if (!trimmedName || !trimmedEmail || !trimmedMessage) {
    return callback(new Error("Name, email, and message cannot be empty"));
  }

  const query = `INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)`;
  db.run(query, [trimmedName, trimmedEmail, trimmedMessage], function (err) {
    if (err) return callback(err);
    callback(null, this.lastID);
  });
}

/**
 * Cart Management Functions
 */

function getCartByUserId(userId, callback) {
  if (typeof callback !== "function") {
    throw new Error("Callback function is required");
  }

  // Convert userId to number if it's a string
  const id = typeof userId === "string" ? parseInt(userId, 10) : userId;

  if (!id || isNaN(id) || id <= 0) {
    return callback(new Error("Valid user ID is required"));
  }

  console.log("Fetching cart for user ID:", id);

  const query = `
    SELECT 
      product_id as id, 
      email, 
      title, 
      price, 
      image, 
      quantity 
    FROM carts 
    WHERE user_id = ?`;

  db.all(query, [id], (err, rows) => {
    if (err) {
      console.error("Error fetching cart:", err);
      return callback(err);
    }
    console.log(`Found ${rows?.length || 0} cart items for user ${id}`);
    callback(null, rows || []);
  });
}

function saveCart(userId, email, cartItems, callback) {
  if (typeof callback !== "function") {
    throw new Error("Callback function is required");
  }

  if (!userId || typeof userId !== "number" || userId <= 0) {
    return callback(new Error("Valid user ID is required"));
  }

  if (!email || typeof email !== "string" || !email.trim()) {
    return callback(new Error("Valid email is required"));
  }

  if (!Array.isArray(cartItems)) {
    return callback(new Error("cartItems must be an array"));
  }

  // Validate each cart item
  for (const item of cartItems) {
    if (!item || typeof item !== "object" || !item.id) {
      return callback(
        new Error("Each cart item must be an object with an id property")
      );
    }
  }

  db.serialize(() => {
    const rollback = (err, dbInstance = db) => {
      dbInstance.run("ROLLBACK", () => callback(err));
    };

    db.run("BEGIN TRANSACTION", (beginErr) => {
      if (beginErr) return rollback(beginErr);

      // Delete existing cart items
      db.run(`DELETE FROM carts WHERE user_id = ?`, [userId], (delErr) => {
        if (delErr) return rollback(delErr);

        // Prepare insert statement
        const insertStmt = db.prepare(`
          INSERT INTO carts (
            user_id, product_id, email, title, price, image, quantity
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `);

        // Insert each item
        let hasInsertError = false;
        for (const item of cartItems) {
          if (hasInsertError) break;

          insertStmt.run(
            userId,
            item.id,
            email.trim(),
            item.title?.trim() || "",
            typeof item.price === "number" ? item.price : 0,
            item.image?.trim() || "",
            typeof item.quantity === "number" && item.quantity > 0
              ? item.quantity
              : 1,
            (insertErr) => {
              if (insertErr) {
                hasInsertError = true;
                return rollback(insertErr, insertStmt);
              }
            }
          );
        }

        // Finalize the statement
        insertStmt.finalize((finalizeErr) => {
          if (finalizeErr || hasInsertError) {
            return rollback(
              finalizeErr || new Error("Insert error"),
              insertStmt
            );
          }

          // Commit if everything succeeded
          db.run("COMMIT", (commitErr) => {
            if (commitErr) return rollback(commitErr);
            callback(null);
          });
        });
      });
    });
  });
}

function addOrUpdateCartItem(userId, email, item, callback) {
  if (typeof callback !== "function") {
    throw new Error("Callback function is required");
  }

  if (!userId || typeof userId !== "number" || userId <= 0) {
    return callback(new Error("Valid user ID is required"));
  }

  if (!email || typeof email !== "string" || !email.trim()) {
    return callback(new Error("Valid email is required"));
  }

  if (!item || typeof item !== "object" || !item.id) {
    return callback(new Error("Item must be an object with an id property"));
  }

  const query = `
    INSERT INTO carts (user_id, product_id, email, title, price, image, quantity)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id, product_id) 
    DO UPDATE SET 
      quantity = quantity + excluded.quantity,
      title = excluded.title,
      price = excluded.price,
      image = excluded.image
  `;

  db.run(
    query,
    [
      userId,
      item.id,
      email.trim(),
      item.title?.trim() || "",
      typeof item.price === "number" ? item.price : 0,
      item.image?.trim() || "",
      typeof item.quantity === "number" && item.quantity > 0
        ? item.quantity
        : 1,
    ],
    function (err) {
      if (err) return callback(err);
      callback(null, this.lastID);
    }
  );
}

function updateCartItemQuantity(userId, productId, quantity, callback) {
  if (typeof callback !== "function") {
    throw new Error("Callback function is required");
  }

  if (!userId || typeof userId !== "number" || userId <= 0) {
    return callback(new Error("Valid user ID is required"));
  }

  if (!productId || typeof productId !== "number" || productId <= 0) {
    return callback(new Error("Valid product ID is required"));
  }

  if (typeof quantity !== "number" || quantity <= 0) {
    return callback(new Error("Quantity must be a positive number"));
  }

  const query = `
    UPDATE carts 
    SET quantity = ? 
    WHERE user_id = ? AND product_id = ?`;

  db.run(query, [quantity, userId, productId], function (err) {
    if (err) return callback(err);
    callback(null, this.changes > 0);
  });
}

function removeCartItem(userId, productId, callback) {
  if (typeof callback !== "function") {
    throw new Error("Callback function is required");
  }

  if (!userId || typeof userId !== "number" || userId <= 0) {
    return callback(new Error("Valid user ID is required"));
  }

  if (!productId || typeof productId !== "number" || productId <= 0) {
    return callback(new Error("Valid product ID is required"));
  }

  const query = `DELETE FROM carts WHERE user_id = ? AND product_id = ?`;
  db.run(query, [userId, productId], function (err) {
    if (err) return callback(err);
    callback(null, this.changes > 0);
  });
}

function clearCart(userId, callback) {
  if (typeof callback !== "function") {
    throw new Error("Callback function is required");
  }

  if (!userId || typeof userId !== "number" || userId <= 0) {
    return callback(new Error("Valid user ID is required"));
  }

  const query = `DELETE FROM carts WHERE user_id = ?`;
  db.run(query, [userId], function (err) {
    if (err) return callback(err);
    callback(null, this.changes > 0);
  });
}

module.exports = {
  db,
  registerUser,
  authenticateUser,
  getUserById,
  getUserByEmail,
  updateUserProfile,
  saveContact,
  getCartByUserId,
  saveCart,
  addOrUpdateCartItem,
  clearCart,
};
