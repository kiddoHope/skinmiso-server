const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const mysql = require('mysql2/promise')
const cors = require("cors");
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const bcrypt = require('bcrypt');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit')
const app = express();
const port = 5000;
const helmet = require('helmet');

app.use(express.static("client"));
app.use(express.json({
  type: ['application/json', 'text/plain']  // Accept JSON or plain text
}));
app.use(bodyParser.json());
app.use(cors({
  origin: ['https://skinmiso.ca', 'https://www.skinmiso.ca', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Authorization', 'Content-Type'],
  credentials: true,
}));

app.options('*', cors());  // Preflight requests


// jwt secret
// const jwtSecret = process.env.REACT_APP_JWT_SECRET;
// jwt secret
const jwtSecret = 'ngekNB082WjQXYBe182Q5p1CbBWc7uDS+S4Axf39zt+aobMcfT7WN4XMEkfzAFtT7TOwZGcGKEkdfRDvvSOV7A==';

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later."
});

// user data backend
// Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Get token from Authorization header

  if (!token) {
    return res.status(401).json({ message: "Authentication token is required" });
  }

  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = decoded;
    next();
  });
};


const db = mysql.createPool({
  host: 'srv1076.hstgr.io',       // Your MySQL server host
  user: 'u781068912_testDatabase',            // Your MySQL username
  password: '2*yKfs:1a',            // Your MySQL password
  database: 'u781068912_skinmiso',    // Your database name
  waitForConnections: true,
  connectTimeout: 20000, // Increase to 20 seconds
  port: 3306,                // Default MySQL port
  connectionLimit: 10,     // Maximum number of connections in the pool
  queueLimit: 0            // Unlimited queueing for connections
});

async function testConnection() {
  try {
    const connection = await db.getConnection();
    console.log('Database connection successful!');
    
    // Test a simple query
    const [rows] = await connection.query('SELECT 1 + 1 AS solution');
    console.log('Query result:', rows);

    connection.release(); // Release the connection back to the pool
  } catch (error) {
    console.error('Database connection failed:', error.message);
  }
}

testConnection();

function generateRandomString(length = 10) {
  return crypto.randomBytes(length).toString('hex').slice(0, length);
}


// Login endpoint
app.post("/api/login", limiter,[
  body('username').notEmpty().withMessage('Username or email is required.'),
  body('password').notEmpty().withMessage('Password is required.')
], async (req, res) => {

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }
  const { username, password } = req.body;

  // Generate login session
  const generatedSession = generateRandomString(20);
  const loginSession = 'sknms' + generatedSession + 'log';

  try {
    // Prepare SQL query to find user by username or email
    const sql = "SELECT * FROM sk_customer_credentials WHERE (user_username = ? OR user_email = ?)";
    const [result] = await db.query(sql, [username, username]);

    // Check if user exists and password is correct
    if (result.length === 1) {
      const user = result[0];
      if (await bcrypt.compare(password, user.user_password)) {
        // Password matches, update login session
        const updateSessionSql = "UPDATE sk_customer_credentials SET user_loginSession = ?, user_activity = 'active' WHERE user_username = ?";
        const [updateResult] = await db.query(updateSessionSql, [loginSession, user.user_username]);

        if (updateResult.affectedRows > 0) {
          // Generate JWT token for the user
          const authToken = jwt.sign({ username: user.user_username }, jwtSecret, { expiresIn: "7d" });
          return res.status(200).json({ success: true, message: 'Login successful', loginSession, token: authToken });
        } else {
          return res.status(500).json({ success: false, message: 'Error creating session' });
        }
      } else {
        // Password doesn't match
        return res.status(401).json({ success: false, message: 'Wrong password' });
      }
    } else {
      // Username or email not found
      return res.status(401).json({ success: false, message: 'No account found' });
    }
  } catch (error) {
    console.error('Database error:', error);
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// create account
app.post("/api/create-acc", limiter, [
  body('customerID').notEmpty().withMessage('Customer ID is required.'),
  body('email').isEmail().withMessage('Invalid email format.'),
  body('mobileno').notEmpty().withMessage('Invalid mobile number.'),
  body('username').trim().escape().notEmpty().withMessage('Username is required.'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long.')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { customerID, email, mobileno, username, password } = req.body;

    // Check if username already exists
    const usernameCheckSql = "SELECT * FROM sk_customer_credentials WHERE user_username = ?";
    const [usernameCheckResults] = await db.query(usernameCheckSql, [username]);
    if (usernameCheckResults.length > 0) {
      return res.status(400).json({ success: false, message: 'Username already exists' });
    }

    // Check if email already exists
    const emailCheckSql = "SELECT * FROM sk_customer_credentials WHERE user_email = ?";
    const [emailCheckResults] = await db.query(emailCheckSql, [email]);
    if (emailCheckResults.length > 0) {
      return res.status(400).json({ success: false, message: 'Email already exists' });
    }

    // If mobileno is not "no phone added", check if it already exists
    if (mobileno !== "no phone added") {
      const mobileCheckSql = "SELECT * FROM sk_customer_credentials WHERE user_mobileno = ?";
      const [mobileCheckResults] = await db.query(mobileCheckSql, [mobileno]);
      if (mobileCheckResults.length > 0) {
        return res.status(400).json({ success: false, message: 'Mobile number already exists' });
      }
    }

    // Hash the password
    const hash_pass = await bcrypt.hash(password, 10);
    const generatedSession = generateRandomString(10);
    const loginSession = 'sknms' + generatedSession + 'log';
    const activity = 'active';

    // Insert data into database
    const insertSql = "INSERT INTO sk_customer_credentials (user_customerID, user_mobileno, user_email, user_username, user_password, user_activity, user_loginSession) VALUES (?, ?, ?, ?, ?, ?, ?)";
    const [insertResult] = await db.query(insertSql, [customerID, mobileno, email, username, hash_pass, activity, loginSession]);

    if (insertResult.affectedRows > 0) {
      const authToken = jwt.sign({ username }, jwtSecret, { expiresIn: "7d" });
      res.status(200).json({ success: true, message: "Customer registered successfully", token: authToken, loginSession });
    } else {
      res.status(500).json({ success: false, message: 'Error registering user' });
    }
  } catch (error) {
    console.error(error); // Log the error for debugging
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


// Logout endpoint
app.post("/api/logout", authenticateToken, async (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ success: false, message: 'Username is required' });
  }

  try {
    // Use the connection pool to query the database
    const connection = await db.getConnection(); // Get a connection from the pool

    try {
      // Check if the user exists
      const [userResult] = await connection.query(
        'SELECT * FROM sk_customer_credentials WHERE user_username = ?',
        [username]
      );

      if (userResult.length === 1) {
        // Update user activity to inactive and clear login session
        const updateSql = 'UPDATE sk_customer_credentials SET user_loginSession = "", user_activity = "inactive" WHERE user_username = ?';
        const [updateResult] = await connection.query(updateSql, [username]);

        if (updateResult.affectedRows > 0) {
          return res.status(200).json({ success: true, message: 'Logout successful' });
        } else {
          return res.status(500).json({ success: false, message: 'Error updating user status' });
        }
      } else {
        return res.status(404).json({ success: false, message: 'User not found' });
      }
    } finally {
      connection.release(); // Always release the connection back to the pool
    }

  } catch (error) {
    console.error('Database error:', error);
    return res.status(500).json({ success: false, message: 'Database connection failed' });
  }
});

// fetch user data
// Protected route to fetch user data
app.get("/api/user-login-access-token", authenticateToken, async (req, res) => {
  try {
    const [allusers] = await db.query("SELECT * FROM sk_customer_credentials");

    const userData = allusers.filter(user => user.user_customerID === req.user.username);
    
    if (!userData) {
      return res.status(404).json({ message: "User data not found" });
    }

    const jsonDatapassed = [userData.user_customerID, userData.user_loginSession];
    res.status(200).json(jsonDatapassed);
  } catch (error) {
    console.error('Database error:', error);
    return res.status(500).json({ success: false, message: 'Database connection failed' });
  }
});

// current user
app.post("/api/user",authenticateToken,async (req, res) => {
  const { userid } = req.body

  if (!userid) {
    return res.status(400).json({ success: false, message: 'customer id is required' });
  }

  try {
    const [allusers] = await db.query("SELECT * FROM sk_customer_credentials");

    const userData = allusers.filter(user => user.user_customerID === userid);
    const cleanedUserData = userData.map(({ id, user_loginSession, user_password, user_role, ...rest }) => rest);
  
    if (cleanedUserData.length > 0) {
      return res.status(200).json({ success: true, data: cleanedUserData });
    } else {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
  } catch (error) {
    console.error('Database error:', error);
    return res.status(500).json({ success: false, message: 'Database connection failed' });
  }
});


// products
// products names only
app.get("/api/products", async (req, res) => {

  try {
    const [allPrdNames] = await db.query("SELECT * FROM sk_products");
    const cleanedPrdnames = allPrdNames.map(prd => {
      const { id,sm_productID, ...rest } = prd;
      return rest;
    });
    res.json(cleanedPrdnames)
  } catch (error) {
    res.json(error)
  }

});

// product data
// Fetch specific product info based on product name
app.post('/api/product-info', async (req, res) => {
  const { product } = req.body;  // Extract the product name from the request body

  if (!product) {
    return res.status(400).json({ error: "Product name is required" });
  }

  let products = {};

  try {

    const connection = await db.getConnection(); // Get a connection from the pool
    // Fetch the specific product by name
    const [productResults] = await connection.query('SELECT * FROM sk_products WHERE sm_product_name = ?', [product]);
    if (productResults.length > 0) {
      products[product] = productResults[0];
    }
    

    // Fetch associated images
    const [imgsResults] = await connection.query('SELECT * FROM sk_product_imgs WHERE sm_product_name = ?', [product]);
    if (imgsResults.length > 0) {
      products[product].images = imgsResults[0];
    }

    // Fetch associated info
    const [infoResults] = await connection.query('SELECT * FROM sk_product_info WHERE sm_product_name = ?', [product]);
    if (infoResults.length > 0) {
      products[product].info = infoResults[0];
    }

    // Fetch associated shorts
    const [shortsResults] = await connection.query('SELECT * FROM sk_product_shorts WHERE sm_product_name = ?', [product]);
    if (shortsResults.length > 0) {
      products[product].shorts = shortsResults[0];
    }
    
    res.status(200).json(products[product]);
  } catch (err) {
    console.error('Error fetching product info:', err.message);
    res.status(500).json({ error: err.message });
  }
});


// add product
app.post("/api/add-product", async (req,res) =>{
  
})

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
