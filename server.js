require("dotenv").config();
const express = require("express");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors());
app.use(express.static("public")); // Serve static files from 'public' directory

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || "your-strong-secret-key"; // Use environment variable in production
const JWT_EXPIRATION = "24h"; // Token expires in 24 hours

// MySQL Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err.stack);
    process.exit(1); // Exit process if connection fails
  }
  console.log("Connected to database.");
});

const checkAuthentication = (req, res, next) => {
  // Get token from Authorization header (Bearer token)
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized. No token provided." });
  }

  const token = authHeader.split(" ")[1];

  try {
    // Verify the token
    const decoded = jwt.verify(token, JWT_SECRET);

    // Add user info to request
    req.userId = decoded.userId;
    req.username = decoded.username;

    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res
        .status(401)
        .json({ error: "Token expired. Please log in again." });
    }
    return res
      .status(401)
      .json({ error: "Invalid token. Please log in again." });
  }
};

app.get("/check-auth", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.json({ authenticated: false });
  }

  const token = authHeader.split(" ")[1];

  try {
    // Verify the token
    const decoded = jwt.verify(token, JWT_SECRET);
    return res.json({ authenticated: true, userId: decoded.userId });
  } catch (error) {
    return res.json({ authenticated: false });
  }
});

// Authentication Routes
app.post("/register", async (req, res) => {
  const { fullName, email, username, password } = req.body;

  if (!fullName || !email || !username || !password) {
    return res.status(400).json({ error: "All fields are required." });
  }

  try {
    // Check if email already exists
    const usernameCheck = "SELECT username FROM users WHERE username = ?";

    db.query(
      usernameCheck,
      username.trim(),
      async (err, usernameCheckResults) => {
        if (err)
          return res.status(500).json({ error: "Internal Server Error" });

        if (usernameCheckResults.length > 0) {
          return res.status(409).json({ error: "Username already exists." });
        }

        // Hash password and create user
        const hashedPassword = await bcrypt.hash(password, 12);

        // Split full name into first and last name
        const nameParts = fullName.trim().split(" ");
        const firstName = nameParts[0];
        const lastName =
          nameParts.length > 1 ? nameParts.slice(1).join(" ") : "";

        //add the user in the db.
        db.query(
          "INSERT INTO users (first_name, last_name, email, username, password) VALUES (?, ?, ?, ?, ?)",
          [firstName, lastName, email.trim(), username.trim(), hashedPassword],
          (err, insertResult) => {
            if (err)
              return res.status(500).json({ error: "Internal Server Error" });

            const userId = insertResult.insertId;

            // Generate JWT token
            const token = jwt.sign(
              { userId, username: username.trim() },
              JWT_SECRET,
              { expiresIn: JWT_EXPIRATION }
            );

            return res.status(201).json({
              success: true,
              message: "User registered successfully",
              token,
              expiresIn: JWT_EXPIRATION,
            });
          }
        );
      }
    );
  } catch (error) {
    console.error("Error during registration:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "username and password are required." });
  }

  try {
    const query = "SELECT * FROM users WHERE username = ?";
    db.query(query, [username.trim()], async (err, results) => {
      if (err) return res.status(500).json({ error: "Internal Server Error" });
      if (results.length === 0) {
        return res.status(401).json({ error: "Invalid username or password." });
      }
      const user = results[0];
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.status(401).json({ error: "Invalid username or password." });
      }

      // Generate JWT token
      const token = jwt.sign(
        { userId: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRATION }
      );

      return res.status(200).json({
        success: true,
        message: "Login successful.",
        token: token,
        expiresIn: JWT_EXPIRATION,
      });
    });
  } catch (error) {
    console.error("Error during login:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

// User Management Routes
app.put("/reset-pass", checkAuthentication, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const userId = req.userId;

  if (!oldPassword || !newPassword) {
    return res
      .status(400)
      .json({ error: "Old password and new password are required." });
  }

  try {
    db.query(
      "SELECT * FROM users WHERE id = ?",
      [userId],
      async (err, results) => {
        if (err)
          return res.status(500).json({ error: "Internal Server Error" });

        if (results.length === 0) {
          return res.status(404).json({ error: "User not found." });
        }

        const user = results[0];
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) {
          return res.status(400).json({ error: "Old password is incorrect." });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 12);
        db.query(
          "UPDATE users SET password = ? WHERE id = ?",
          [hashedPassword, userId],
          (err) => {
            if (err)
              return res.status(500).json({ error: "Internal Server Error" });

            // Generate new token after password change
            const token = jwt.sign(
              { userId, username: user.username },
              JWT_SECRET,
              { expiresIn: JWT_EXPIRATION }
            );

            return res.status(200).json({
              success: true,
              message: "Password updated successfully.",
              token,
              expiresIn: JWT_EXPIRATION,
            });
          }
        );
      }
    );
  } catch (error) {
    console.error("Error resetting password:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.put("/edit-user", checkAuthentication, async (req, res) => {
  const { firstname, lastname, username } = req.body;
  const userId = req.userId;

  if (!firstname || !lastname || !username) {
    return res.status(400).json({ error: "All fields are required." });
  }

  try {
    db.query(
      "UPDATE users SET first_name = ?, last_name = ?, username = ? WHERE id = ?",
      [firstname.trim(), lastname.trim(), username.trim(), userId],
      (err) => {
        if (err)
          return res.status(500).json({ error: "Internal Server Error" });

        // Generate new token if username was changed
        const token = jwt.sign(
          { userId, username: username.trim() },
          JWT_SECRET,
          { expiresIn: JWT_EXPIRATION }
        );

        return res.status(200).json({
          success: true,
          message: "User details updated successfully.",
          token,
          expiresIn: JWT_EXPIRATION,
        });
      }
    );
  } catch (error) {
    console.error("Error updating user:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/get-user", checkAuthentication, async (req, res) => {
  const userId = req.userId;

  try {
    db.query(
      "SELECT first_name, last_name, username, email FROM users WHERE id = ?",
      [userId],
      (err, results) => {
        if (err)
          return res.status(500).json({ error: "Internal Server Error" });

        if (results.length === 0) {
          return res.status(404).json({ error: "User not found." });
        }

        const user = results[0];
        return res.status(200).json({
          success: true,
          user: {
            first_name: user.first_name,
            last_name: user.last_name,
            username: user.username,
            email: user.email,
          },
        });
      }
    );
  } catch (error) {
    console.error("Error getting user:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

// Dashboard API Routes
app.get("/api/dashboard/stats/", checkAuthentication, (req, res) => {
  try {
    const userId = req.userId;
    // Query for total products count
    db.query(
      "SELECT COUNT(*) as totalProducts FROM products WHERE user_id = ?",
      [userId],
      (err, productResults) => {
        if (err)
          return res.status(500).json({ error: "Internal Server Error" });

        const totalProducts = productResults[0].totalProducts;

        // Query for low stock items count (where current_stock <= minimum_stock)
        db.query(
          "SELECT COUNT(*) as lowStockItems FROM products WHERE current_stock <= minimum_stock AND user_id = ?",
          [userId],
          (err, lowStockResults) => {
            if (err)
              return res.status(500).json({ error: "Internal Server Error" });

            const lowStockItems = lowStockResults[0].lowStockItems;

            // Query for total categories
            db.query(
              "SELECT COUNT(*) as totalCategories FROM categories WHERE user_id = ?",
              [userId],
              (err, categoryResults) => {
                if (err)
                  return res
                    .status(500)
                    .json({ error: "Internal Server Error" });

                const totalCategories = categoryResults[0].totalCategories;

                // Query for total inventory value
                db.query(
                  "SELECT SUM(current_stock * price) as totalValue FROM products WHERE user_id = ?",
                  [userId],
                  (err, valueResults) => {
                    if (err)
                      return res
                        .status(500)
                        .json({ error: "Internal Server Error" });

                    const totalValue = valueResults[0].totalValue || 0;

                    return res.status(200).json({
                      totalProducts,
                      lowStockItems,
                      totalCategories,
                      totalValue,
                    });
                  }
                );
              }
            );
          }
        );
      }
    );
  } catch (error) {
    console.error("Error fetching dashboard stats:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get(
  "/api/dashboard/stock-by-category/",
  checkAuthentication,
  (req, res) => {
    const userId = req.userId;
    try {
      db.query(
        `SELECT c.name, SUM(p.current_stock) as totalStock 
       FROM products p 
       JOIN categories c ON p.category_id = c.id  WHERE p.user_id = ?
       GROUP BY c.id 
       ORDER BY totalStock DESC 
       LIMIT 5;`,
        [userId],
        (err, results) => {
          if (err)
            return res.status(500).json({ error: "Internal Server Error" });

          const categories = results.map((item) => item.name);
          const stockLevels = results.map((item) => item.totalStock);

          return res.status(200).json({
            categories,
            stockLevels,
          });
        }
      );
    } catch (error) {
      console.error("Error fetching stock by category:", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }
  }
);

app.get("/api/dashboard/sales-trend/", checkAuthentication, (req, res) => {
  const userId = req.userId;
  try {
    // Assuming you have a sales_history table with date and amount columns
    db.query(
      `SELECT 
    DATE_FORMAT(sale_date, '%Y-%m') AS month,
    SUM(amount) AS sales
    FROM sales_history
    WHERE sale_date >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH) AND user_id = ?
    GROUP BY DATE_FORMAT(sale_date, '%Y-%m')
    ORDER BY DATE_FORMAT(sale_date, '%Y-%m') ASC;
    `,
      [userId],
      (err, results) => {
        if (err)
          return res
            .status(500)
            .json({ error: "Internal Server Error", er: err });

        const months = results.map((item) => item.month);
        const salesData = results.map((item) => item.sales);

        return res.status(200).json({
          months,
          salesData,
        });
      }
    );
  } catch (error) {
    console.error("Error fetching sales trend:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/dashboard/low-stock/", checkAuthentication, (req, res) => {
  const userId = req.userId;
  try {
    db.query(
      `SELECT 
        p.id, 
        p.name, 
        p.current_stock as currentStock, 
        p.minimum_stock as minimumRequired 
       FROM products p 
       WHERE p.current_stock <= p.minimum_stock AND user_id = ?
       ORDER BY (p.current_stock / p.minimum_stock) ASC`,
      [userId],
      (err, results) => {
        if (err)
          return res.status(500).json({ error: "Internal Server Error" });

        return res.status(200).json(results);
      }
    );
  } catch (error) {
    console.error("Error fetching low stock items:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

//product apis

//get all products
app.get("/get-products/", checkAuthentication, (req, res) => {
  const userId = req.userId;
  const productQuery =
    "SELECT products.name, products.current_stock, products.price, products.minimum_stock, products.status, categories.name as category FROM products INNER JOIN categories ON products.category_id = categories.id WHERE products.user_id = ? AND categories.status = ?";

  db.query(productQuery, [userId, "active"], (prodErr, productResults) => {
    if (prodErr)
      return res.status(500).json({ error: "Internal Server Error", prodErr });
    res.status(200).json({ success: true, products: productResults });
  });
});

// Create Product Route
app.post("/add-product", (req, res) => {
  const { name, size, color, price, qty, threshold, status } = req.body;

  // Validate required fields
  if (!name || !size || !color || !price || !qty || !threshold || !status) {
    res.status(400).json({ error: "All fields are required." });
    return;
  }

  const query = `
    INSERT INTO products (name, size, color, price, qty, threshold, status) 
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(
    query,
    [name, size, color, price, qty, threshold, status],
    (err, result) => {
      if (err) {
        console.error("Error adding product:", err);
        res
          .status(500)
          .json({ error: "An error occurred while adding the product." });
        return;
      }

      res.status(201).json({
        success: 1,
        productId: result.insertId,
      });
    }
  );
});

// Get Product by ID
app.get("/get-product/:id", (req, res) => {
  const productId = req.params.id;

  const query = "SELECT * FROM products WHERE id = ?";
  db.query(query, [productId], (err, result) => {
    if (err) {
      console.error("Error fetching product:", err);
      res
        .status(500)
        .json({ error: "An error occurred while fetching the product." });
      return;
    }

    if (result.length === 0) {
      res.status(404).json({ error: "Product not found." });
      return;
    }

    res.status(200).json({ product: result[0] });
  });
});

// Update Existing Product
app.put("/update-product/", (req, res) => {
  const { id } = req.params; // Product ID from URL
  const { name, size, color, price, qty, status, threshold } = req.body; // Updated product details from request body

  // Input Validation
  if (!name || !size || !color || !price || !qty || !status || !threshold) {
    return res.status(400).json({ error: "All product fields are required." });
  }

  // SQL query to update product details
  const updateQuery =
    "UPDATE products SET name = ?, qty = ?, price = ?, size = ?, color = ?, status = ?, threshold = ? WHERE id = ?";
  db.query(
    updateQuery,
    [
      name.trim(),
      qty,
      price,
      size.trim(),
      color.trim(),
      status.trim(),
      threshold,
      id,
    ],
    (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      if (results.affectedRows === 0) {
        return res.status(404).json({ error: "Product not found." });
      }

      return res.status(200).json({ success: 1 });
    }
  );
});

// Delete Product - DELETE /products/:id
app.delete("/delete-product/:id", (req, res) => {
  const { id } = req.params; // Product ID from URL

  // SQL query to delete the product
  const deleteQuery = "DELETE FROM products WHERE id = ?";
  db.query(deleteQuery, [id], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ error: "Product not found." });
    }

    return res.status(200).json({ success: 1 });
  });
});

// Shop Route (POST) to update product quantity based on the purchase
app.put("/replenish", (req, res) => {
  const { productId, quantity } = req.body;

  if (!productId || !quantity) {
    return res
      .status(400)
      .json({ error: "Product ID and quantity are required." });
  }

  // Get the current quantity and threshold from the products table
  const query = `SELECT current_stock FROM products WHERE id = ?`;

  db.query(query, [productId], (err, results) => {
    if (err) {
      console.error("Error fetching product data:");
      return res
        .status(500)
        .json({ error: "Failed to fetch product details." });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "Product not found." });
    }

    const currentQty = results[0].current_stock;
    const newQty = currentQty + quantity;
    const currentMinium = results[0].current_minium;
    const updateQty = `UPDATE products SET current_stock = ? WHERE id = ?`;

    const updateStatus = `UPDATE products SET status = ? WHERE id = ?`;
    let status;
    if (currentMinium > newQty) {
      status = "available";
    } else {
      status = "low";
    }
    // Perform the update query
    db.query(updateQty, [newQty, productId], (err, updateResults) => {
      if (err) {
        console.error("Error updating product data:", err);
        return res.status(500).json({ error: "Failed to update product." });
      }

      res.status(200).json({ success: true, message: "Quantity Updated" });
    });
  });
});

// Add token refresh endpoint
app.post("/refresh-token", checkAuthentication, (req, res) => {
  // Since we already verified the token in checkAuthentication middleware,
  // we can generate a new token
  const token = jwt.sign(
    { userId: req.userId, username: req.username },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRATION }
  );

  return res.status(200).json({
    success: true,
    token,
    expiresIn: JWT_EXPIRATION,
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
