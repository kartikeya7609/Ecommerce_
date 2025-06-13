const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");

// Load environment variables from node.env file using absolute path
require("dotenv").config({ path: path.join(__dirname, "node.env") });

const { db, registerUser, authenticateUser, getUserById } = require("./db");

// Define DB_PATH for health check endpoint
const DB_PATH = path.join(__dirname, "users.db");

// Validate environment variables
const requiredEnvVars = [
  "ACCESS_TOKEN_SECRET",
  "REFRESH_TOKEN_SECRET",
  "PORT",
  "NODE_ENV",
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`FATAL ERROR: ${envVar} not configured`);
    process.exit(1);
  }
}

const app = express();
const PORT = process.env.PORT || 3002;

// Enhanced CORS configuration
const corsOptions = {
  origin:
    process.env.NODE_ENV === "production"
      ? process.env.CORS_ORIGIN_PROD
      : process.env.CORS_ORIGIN_DEV || "http://localhost:3000",
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization"],
};

function generateAccessToken(user) {
  console.log("Generating access token for user:", {
    id: user.id,
    email: user.email,
  });
  return jwt.sign(
    { id: user.id, email: user.email },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || "15m" }
  );
}

function generateRefreshToken(user) {
  console.log("Generating refresh token for user:", {
    id: user.id,
    email: user.email,
  });
  return jwt.sign(
    { id: user.id, email: user.email },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || "7d" }
  );
}

// Middlewares
app.use(cors(corsOptions));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// Request logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      error: "Authorization token required",
      code: "MISSING_TOKEN",
    });
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      console.error("JWT verification error:", err);
      return res.status(403).json({
        error: "Invalid or expired token",
        code: "INVALID_TOKEN",
      });
    }
    req.user = user;
    next();
  });
}

// ====== Public Routes ======

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    timestamp: new Date(),
    db: fs.existsSync(DB_PATH) ? "Connected" : "Disconnected",
  });
});

// Register user
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    console.log("Registration attempt for:", { name, email });

    if (!name || !email || !password) {
      console.log("Missing required fields");
      return res.status(400).json({
        error: "Name, email, and password are required.",
        code: "MISSING_FIELDS",
      });
    }

    registerUser(name, email, password, (err, userId) => {
      if (err) {
        console.error("Registration error:", err);
        if (err.message === "Email already exists") {
          return res.status(409).json({
            error: "Email already registered",
            code: "EMAIL_EXISTS",
          });
        }
        return res.status(500).json({
          error: "Registration failed",
          code: "DB_ERROR",
        });
      }
      console.log("User registered successfully with ID:", userId);
      res.status(201).json({
        message: "User registered successfully",
        userId: userId,
      });
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      error: "Registration failed",
      code: "SERVER_ERROR",
    });
  }
});

// Login user
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log("Login attempt for email:", email);

    if (!email || !password) {
      console.log("Missing email or password");
      return res.status(400).json({ error: "Email and password are required" });
    }

    authenticateUser(email, password, (err, user) => {
      if (err) {
        console.error("Authentication error:", err);
        return res.status(500).json({ error: "Authentication failed" });
      }
      if (!user) {
        console.log("No user found or invalid password for email:", email);
        return res.status(401).json({ error: "Invalid email or password" });
      }

      console.log("User authenticated successfully:", {
        id: user.id,
        email: user.email,
      });

      // Generate tokens
      const accessToken = generateAccessToken(user);
      const refreshToken = generateRefreshToken(user);

      // Set refresh token in HTTP-only cookie
      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: "/",
      });

      console.log("Refresh token set in cookie");

      // Send response with access token and user data
      const responseData = {
        token: accessToken,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
        },
      };

      console.log("Sending response to client:", {
        token: "[REDACTED]",
        user: responseData.user,
      });
      res.json(responseData);
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Login failed" });
  }
});

// Refresh token endpoint
app.post("/api/auth/refresh", async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    console.log("Received refresh token:", refreshToken ? "exists" : "missing");

    if (!refreshToken) {
      console.log("No refresh token found in cookies");
      return res.status(401).json({ error: "No refresh token" });
    }

    console.log("Attempting to verify refresh token");

    try {
      const decoded = jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET
      );
      console.log("Decoded refresh token:", decoded);

      if (!decoded.id) {
        console.error("No user ID in refresh token");
        return res.status(403).json({ error: "Invalid refresh token format" });
      }

      console.log("Looking up user with ID:", decoded.id);

      getUserById(decoded.id, (err, user) => {
        if (err) {
          console.error("Error fetching user for refresh token:", err);
          return res
            .status(500)
            .json({ error: "Server error during token refresh" });
        }

        if (!user) {
          console.error(
            "User not found for refresh token with ID:",
            decoded.id
          );
          return res
            .status(403)
            .json({ error: "Invalid refresh token - user not found" });
        }

        console.log("User found for refresh token:", {
          id: user.id,
          email: user.email,
        });

        // Generate new tokens
        const accessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);

        // Set new refresh token in HTTP-only cookie
        res.cookie("refreshToken", newRefreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
          path: "/",
        });

        console.log("New refresh token set in cookie");

        // Send response with new access token
        const responseData = {
          token: accessToken,
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
          },
        };

        console.log("Sending refresh response to client:", {
          token: "[REDACTED]",
          user: responseData.user,
        });
        res.json(responseData);
      });
    } catch (err) {
      console.error("Token verification error:", err);
      return res.status(403).json({ error: "Invalid refresh token" });
    }
  } catch (error) {
    console.error("Refresh token error:", error);
    res.status(500).json({ error: "Token refresh failed" });
  }
});

// Contact form endpoint
app.post("/api/contact", authenticateToken, async (req, res) => {
  try {
    const { name, email, message } = req.body;

    if (!name || !email || !message) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const { saveContact } = require("./db");
    saveContact(name, email, message, (err, contactId) => {
      if (err) {
        console.error("Contact form error:", err);
        return res
          .status(500)
          .json({ error: "Failed to save contact message" });
      }
      res.json({
        message: "Message received successfully",
        contactId: contactId,
      });
    });
  } catch (error) {
    console.error("Contact form error:", error);
    res.status(500).json({ error: "Failed to process contact form" });
  }
});

// Token verification endpoint
app.get("/api/auth/verify", authenticateToken, async (req, res) => {
  try {
    getUserById(req.user.id, (err, user) => {
      if (err) {
        console.error("Error fetching user:", err);
        return res.status(500).json({ error: "Internal server error" });
      }
      if (!user) {
        return res.status(401).json({ error: "User not found" });
      }

      res.json({
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
        },
      });
    });
  } catch (error) {
    console.error("Token verification error:", error);
    res.status(401).json({ error: "Invalid token" });
  }
});

// ====== Protected Routes (require authentication) ======

// Get user profile
app.get("/api/user/:userId", authenticateToken, async (req, res) => {
  try {
    const userId = parseInt(req.params.userId, 10);
    console.log("Fetching profile for user ID:", userId);

    if (!userId || isNaN(userId)) {
      console.error("Invalid user ID in request:", req.params.userId);
      return res
        .status(400)
        .json({ error: "Invalid user ID", code: "INVALID_USER_ID" });
    }

    // Log the authenticated user
    console.log("Authenticated user:", req.user);

    getUserById(userId, (err, user) => {
      if (err) {
        console.error("Error fetching user profile:", err);
        // Send more specific error messages based on the error type
        if (err.message.includes("Database connection")) {
          return res.status(500).json({
            error: "Database connection error",
            code: "DB_CONNECTION_ERROR",
          });
        }
        return res.status(500).json({
          error: "Database error",
          code: "DB_ERROR",
          details: err.message,
        });
      }

      if (!user) {
        console.log("User not found with ID:", userId);
        return res.status(404).json({
          error: "User not found",
          code: "USER_NOT_FOUND",
        });
      }

      console.log("User profile found:", user);
      res.json(user);
    });
  } catch (error) {
    console.error("Error in user profile endpoint:", error);
    res.status(500).json({
      error: "Server error",
      code: "SERVER_ERROR",
      details: error.message,
    });
  }
});

// Update user profile
app.put("/api/user/:userId", authenticateToken, (req, res) => {
  try {
    const { userId } = req.params;
    const { name, username, bio, location, website } = req.body;

    if (!userId || isNaN(userId)) {
      return res.status(400).json({
        error: "Invalid user ID",
        code: "INVALID_USER_ID",
      });
    }

    const query = `
      UPDATE users
      SET name = ?, username = ?, bio = ?, location = ?, website = ?
      WHERE id = ?
    `;

    db.run(
      query,
      [
        name || "",
        username || "",
        bio || "",
        location || "",
        website || "",
        userId,
      ],
      function (err) {
        if (err) {
          console.error("Failed to update profile:", err);
          return res.status(500).json({
            error: "Database update failed",
            code: "DB_ERROR",
          });
        }
        if (this.changes === 0) {
          return res.status(404).json({
            error: "User not found",
            code: "USER_NOT_FOUND",
          });
        }
        res.json({ message: "Profile updated successfully" });
      }
    );
  } catch (error) {
    console.error("Update user error:", error);
    res.status(500).json({
      error: "Failed to update user",
      code: "SERVER_ERROR",
    });
  }
});

// Cart fetch endpoint
app.get("/api/cart", authenticateToken, async (req, res) => {
  try {
    // Using the database functions from db.js instead of Cart model
    const { getCartByUserId } = require("./db");
    console.log("Fetching cart for user:", req.user.id);

    getCartByUserId(req.user.id, (err, cartItems) => {
      if (err) {
        console.error("Cart fetch error:", err);
        return res.status(500).json({ error: "Error fetching cart" });
      }

      // Return empty array if no items found
      if (!cartItems || cartItems.length === 0) {
        console.log(`No cart items found for user ${req.user.id}`);
        return res.json({ items: [], message: "No items in cart" });
      }

      console.log(
        `Returning ${cartItems.length} cart items for user ${req.user.id}`
      );
      res.json({ items: cartItems || [] });
    });
  } catch (error) {
    console.error("Cart fetch error:", error);
    res.status(500).json({ error: "Error fetching cart" });
  }
});

// Add or update cart item
app.post("/api/cart", authenticateToken, async (req, res) => {
  try {
    // Using the database functions from db.js instead of Cart model
    const { addOrUpdateCartItem, getCartByUserId } = require("./db");
    const userId = req.user.id;
    const { productId, quantity, title, price, image } = req.body;

    console.log(
      "Adding/updating cart item for user:",
      userId,
      "product:",
      productId
    );

    addOrUpdateCartItem(
      userId,
      req.user.email,
      {
        id: productId,
        title,
        price,
        image,
        quantity: quantity || 1,
      },
      (err, cartItemId) => {
        if (err) {
          console.error("Cart update error:", err);
          return res.status(500).json({ error: "Failed to update cart" });
        }

        // Return updated cart
        getCartByUserId(userId, (err, cartItems) => {
          if (err) {
            console.error("Cart fetch error after update:", err);
            return res
              .status(500)
              .json({ error: "Error fetching updated cart" });
          }
          res.json({ items: cartItems || [] });
        });
      }
    );
  } catch (error) {
    console.error("Cart update error:", error);
    res.status(500).json({ error: "Failed to update cart" });
  }
});

// Update cart item quantity
app.put("/api/cart/:productId", authenticateToken, async (req, res) => {
  try {
    const { updateCartItemQuantity, getCartByUserId } = require("./db");
    const userId = req.user.id;
    const productId = parseInt(req.params.productId, 10);
    const { quantity } = req.body;

    console.log(
      "Updating cart item quantity for user:",
      userId,
      "product:",
      productId,
      "quantity:",
      quantity
    );

    if (!productId || isNaN(productId)) {
      return res.status(400).json({ error: "Invalid product ID" });
    }

    if (!quantity || isNaN(quantity) || quantity < 1) {
      return res.status(400).json({ error: "Invalid quantity" });
    }

    updateCartItemQuantity(userId, productId, quantity, (err, success) => {
      if (err) {
        console.error("Cart quantity update error:", err);
        return res
          .status(500)
          .json({ error: "Failed to update cart item quantity" });
      }

      if (!success) {
        return res.status(404).json({ error: "Cart item not found" });
      }

      // Return updated cart
      getCartByUserId(userId, (err, cartItems) => {
        if (err) {
          console.error("Cart fetch error after quantity update:", err);
          return res.status(500).json({ error: "Error fetching updated cart" });
        }
        res.json({ items: cartItems || [] });
      });
    });
  } catch (error) {
    console.error("Cart quantity update error:", error);
    res.status(500).json({ error: "Failed to update cart item quantity" });
  }
});

// Remove cart item
app.delete("/api/cart/:productId", authenticateToken, async (req, res) => {
  try {
    const { removeCartItem, getCartByUserId } = require("./db");
    const userId = req.user.id;
    const productId = parseInt(req.params.productId, 10);

    console.log("Removing cart item for user:", userId, "product:", productId);

    if (!productId || isNaN(productId)) {
      return res.status(400).json({ error: "Invalid product ID" });
    }

    removeCartItem(userId, productId, (err, success) => {
      if (err) {
        console.error("Cart item removal error:", err);
        return res.status(500).json({ error: "Failed to remove cart item" });
      }

      if (!success) {
        return res.status(404).json({ error: "Cart item not found" });
      }

      // Return updated cart
      getCartByUserId(userId, (err, cartItems) => {
        if (err) {
          console.error("Cart fetch error after item removal:", err);
          return res.status(500).json({ error: "Error fetching updated cart" });
        }
        res.json({ items: cartItems || [] });
      });
    });
  } catch (error) {
    console.error("Cart item removal error:", error);
    res.status(500).json({ error: "Failed to remove cart item" });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({
    error: "Internal server error",
    code: "INTERNAL_ERROR",
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: `Endpoint ${req.method} ${req.path} not found`,
    code: "NOT_FOUND",
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📎 API Documentation:`);
  console.log(`- POST   /api/auth/register - Register new user`);
  console.log(`- POST   /api/auth/login    - User login`);
  console.log(`- POST   /api/auth/refresh  - Refresh access token`);
  console.log(`- GET    /api/auth/verify   - Verify token`);
  console.log(`- GET    /api/user/:id      - Get user profile (protected)`);
  console.log(`- PUT    /api/user/:id      - Update profile (protected)`);
  console.log(`- GET    /api/cart          - Get user cart (protected)`);
  console.log(`- POST   /api/cart          - Update user cart (protected)`);
});
