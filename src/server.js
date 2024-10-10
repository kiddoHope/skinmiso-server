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
const { jwtDecode } = require('jwt-decode')
const app = express();
const port = 5000;
const axios = require('axios')
const { OAuth2Client } = require('google-auth-library');

app.use(bodyParser.json());

const allowedOrigins = ['https://skinmiso.ca', 'http://localhost:3000', 'https://skinmiso.vercel.app'];
app.options('*', cors()); // Allow preflight requests for all routes
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin, like mobile apps or curl requests
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-access-token', 'X-Requested-With','Accept'],
  credentials: true, // Allow credentials (cookies, etc.) in CORS requests
}));


// jwt secret
// const jwtSecret = process.env.REACT_APP_JWT_SECRET;
// jwt secret
const jwtSecret = process.env.REACT_APP_JWT_SECRET
const googleClientID = process.env.REACT_GOOGLE_CLIENT_ID

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
app.post("/api/register-acc", limiter, [
  body('email').isEmail().withMessage('Invalid email format.'),
  body('mobileno').notEmpty().withMessage('Invalid mobile number.'),
  body('username').notEmpty().withMessage('Username is required.'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long.')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const customerID = 'skms_' + generateRandomString(10)
    const { email, mobileno, username, password } = req.body;

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
    const userRole = 'customer'
    const loginSession = 'sknms' + generatedSession + 'log';
    const activity = 'active';

    // Insert data into database
      const insertSql = "INSERT INTO sk_customer_credentials (user_customerID, user_mobileno, user_email, user_username, user_password, user_role, user_activity, user_loginSession) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
      const [insertResult] = await db.query(insertSql, [customerID, mobileno, email, username, hash_pass, userRole, activity, loginSession]);
    
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

    const userData = allusers.filter(user => user.user_username === req.user.username);
    
    if (!userData) {
      return res.status(404).json({ message: "User data not found" });
    }

    const jsonDatapassed = [userData[0].user_customerID, userData[0].user_loginSession];
    
    res.status(200).json(jsonDatapassed);
  } catch (error) {
    console.error('Database error:', error);
    return res.status(500).json({ success: false, message: 'Database connection failed' });
  }
});

// current user
app.post("/api/user",authenticateToken,async (req, res) => {
  const { userAuth } = req.body

  if (!userAuth) {
    return res.status(400).json({ success: false, message: 'no auth token retrieve' });
  }

  const authDecode = jwtDecode(userAuth.userToken)
  const expData = authDecode.exp

  const currentTime = Math.floor(Date.now() / 1000);
  if (currentTime > expData) {
    return res.status(400).json({ success: false, message: 'login expired' });
  }

  try {
    const [allusers] = await db.query("SELECT * FROM sk_customer_credentials");

    const userData = allusers.filter(user => user.user_username === authDecode.username);
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



// fb login
app.post("/api/connect-to-fb", async (req, res) => {
  const { accessToken } = req.body;
  
  if (accessToken) {
    try {
      const response = await axios.get(`https://graph.facebook.com/v20.0/me`, {
        method: "GET",
        headers: {
          'Content-Type': 'application/json',
        },
        params: {
          access_token: accessToken,
          fields: 'id,name,email,picture,first_name' // Specify the fields you want
        }
      });

      const userRole = 'customer';
      const fbConnected = 'connected';
      const customerID = 'skms_' + generateRandomString(10);
      const fbData = response.data;
      const email = fbData.email;
      const username = fbData.first_name;
      const mobileno = 'no phone added';
      const hash_pass = '';
      const generatedSession = generateRandomString(10);
      const loginSession = 'sknms' + generatedSession + 'log';
      const activity = 'active';
      const fbID = fbData.id;

      const emailCheckSql = "SELECT * FROM sk_customer_credentials WHERE user_email = ?";
      const [emailCheckResults] = await db.query(emailCheckSql, [email]);

      if (emailCheckResults.length > 0) {
        const userID = emailCheckResults[0].user_customerID;
        
        const connected = emailCheckResults[0].user_fb_connected;

        if (connected === 'connected') {
          const authToken = jwt.sign({ username }, jwtSecret, { expiresIn: "7d" });
          // Push to login
          return res.status(200).json({ success: true, message: "Customer Login successfully", token: authToken, loginSession,facebook: connected});
        } else {
          // Update Facebook connection status
          const updateData = "UPDATE sk_customer_credentials SET user_fb_connected = ? WHERE user_customerID = ?";
          const [updateDataResult] = await db.query(updateData, [fbConnected, userID]);

          if (updateDataResult.affectedRows > 0) {
            // Insert Facebook info if update was successful
            const insertFBinfo = "INSERT INTO sk_customer_facebook (user_customerID, user_facebookID) VALUES (?, ?)";
            const [insertFBData] = await db.query(insertFBinfo, [userID, fbID]);
            
            if (insertFBData.affectedRows > 0) {
              const authToken = jwt.sign({ username }, jwtSecret, { expiresIn: "7d" });
              return res.status(200).json({ success: true, message: "Customer Login successfully", token: authToken, loginSession, customerID: userID });
            } else {
              return res.status(500).json({ success: false, message: 'Error registering Facebook Account' });
            }
          } else {
            return res.status(500).json({ success: false, message: 'Error updating customer credentials' });
          }
        }
      }

      // If user does not exist, insert new user data
      const insertSql = "INSERT INTO sk_customer_credentials (user_customerID, user_mobileno, user_email, user_username, user_password, user_role, user_fb_connected, user_activity, user_loginSession) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
      const [insertResult] = await db.query(insertSql, [customerID, mobileno, email, username, hash_pass, userRole, fbConnected, activity, loginSession]);

      if (insertResult.affectedRows > 0) {
        const insertFBinfo = "INSERT INTO sk_customer_facebook (user_customerID, user_facebookID) VALUES (?, ?)";
        const [insertFBData] = await db.query(insertFBinfo, [customerID, fbID]);
        
        if (insertFBData.affectedRows > 0) {
          const authToken = jwt.sign({ username }, jwtSecret, { expiresIn: "7d" });
          return res.status(200).json({ success: true, message: "Customer registered successfully", token: authToken, loginSession});
        } else {
          return res.status(500).json({ success: false, message: 'Error Registering Facebook Account' });
        }
      } else {
        return res.status(500).json({ success: false, message: 'Error registering user' });
      }
    } catch (error) {
      console.error(error);
      return res.status(500).json({ success: false, message: 'Server Error' });
    }
  } else {
    console.log('No data received');
    return res.status(400).json({ success: false, message: 'Access token is required' });
  }
});

// connect to google
// const client = new OAuth2Client(googleClientID);

// app.post('/api/google-signin', async (req, res) => {
//   const { decoded } = req.body;
//   console.log(decoded);
// });


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

// Fetch specific product info based on product name
app.post('/api/product-info', async (req, res) => {
  const { productName } = req.body;  // Extract the product name from the request body

  if (!productName) {
    return res.status(400).json({ error: "Product name is required" });
  }

  let products = {};

  try {

    const connection = await db.getConnection(); // Get a connection from the pool
    // Fetch the specific product by name
    const [productResults] = await connection.query('SELECT * FROM sk_products WHERE sm_product_name = ?', [productName]);
    if (productResults.length > 0) {
      products[productName] = productResults[0];
    }
    

    // Fetch associated images
    const [imgsResults] = await connection.query('SELECT * FROM sk_product_imgs WHERE sm_product_name = ?', [productName]);
    if (imgsResults.length > 0) {
      products[productName].images = imgsResults[0];
    }

    // Fetch associated info
    const [infoResults] = await connection.query('SELECT * FROM sk_product_info WHERE sm_product_name = ?', [productName]);
    if (infoResults.length > 0) {
      products[productName].info = infoResults[0];
    }

    // Fetch associated shorts
    const [shortsResults] = await connection.query('SELECT * FROM sk_product_shorts WHERE sm_product_name = ?', [productName]);
    if (shortsResults.length > 0) {
      products[productName].shorts = shortsResults[0];
    }
    
    res.status(200).json(products[productName]);
  } catch (err) {
    console.error('Error fetching product info:', err.message);
    res.status(500).json({ error: err.message });
  }
});




app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
