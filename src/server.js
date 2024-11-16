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
const axios = require('axios')
const cheerio = require('cheerio');
const atob = require('atob');
const multer = require("multer");
const FormData = require("form-data");
const fs = require('fs');
const path = require('path');

const postFile = path.join(__dirname, 'jsonData.json');


app.use(bodyParser.json());
const upload = multer({ storage: multer.memoryStorage() });

const allowedOrigins = ['https://skinmiso.ca', 'https://skinmiso.ph', 'http://localhost:3000', 'https://skinmiso.vercel.app', 'https://skinmiso-ph-beta.vercel.app', 'http://localhost:3001'];

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
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-access-token', 'X-Requested-With', 'Accept'],
  credentials: true, // Allow credentials (cookies, etc.) in CORS requests
}));

// Handle preflight requests
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE', 'PATCH');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-access-token, X-Requested-With, Accept');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(204);
});

// Set Vary header to Origin
app.use((req, res, next) => {
  res.header('Vary', 'Origin');
  next();
});


// jwt secret
// const jwtSecret = process.env.REACT_APP_JWT_SECRET;
// jwt secret
const jwtSecret = process.env.REACT_APP_JWT_SECRET
// const googleClientID = process.env.REACT_GOOGLE_CLIENT_ID

const jwtDecode = (token) => {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
  } catch (error) {
    throw new Error('Invalid token specified');
  }
};

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

app.post('/api/land-post', (req, res) => {
  fs.readFile(postFile, 'utf8', (err, data) => {
      if (err) {
          console.error("Error reading the file:", err);
          return res.status(500).json({ error: "Failed to read data" });
      }
      
      try {
          const jsonData = JSON.parse(data);
          res.json(jsonData); // Sends the JSON data as a response
      } catch (parseErr) {
          console.error("Error parsing JSON data:", parseErr);
          res.status(500).json({ error: "Invalid JSON format" });
      }
  });
});

app.patch('/api/update-like', (req, res) => {
  const { postIndex, isLike } = req.body;

  fs.readFile(postFile, 'utf8', (err, data) => {
    if (err) {
      console.error('Error reading data:', err);
      return res.status(500).send('Error reading data');
    }

    try {
      const postData = JSON.parse(data);
      // Check if postIndex is valid
      if (!postData[postIndex] || !postData[postIndex].post) {
        return res.status(400).send('Invalid post index');
      }

      // Update likeCount based on isLike value
      postData[postIndex].post.likeCount += isLike ? -1 : 1;

      // Write updated data back to the file
      fs.writeFile(postFile, JSON.stringify(postData, null, 2), (writeErr) => {
        if (writeErr) {
          console.error('Error writing data:', writeErr);
          return res.status(500).send('Error writing data');
        }
        res.send('Post updated successfully');
      });
    } catch (parseErr) {
      console.error('Error parsing JSON data:', parseErr);
      res.status(500).send('Invalid JSON format');
    }
  });
});


app.patch('/api/update-comment-like', (req, res) => {
  const { postIndex, commentIndex, isLike } = req.body;
  fs.readFile(postFile, 'utf8', (err, data) => {
    if (err) {
      console.error('Error reading data:', err);
      return res.status(500).send('Error reading data');
    }

    try {
      const postData = JSON.parse(data);
      
      if (!postData[postIndex] || !postData[postIndex].post.comments[commentIndex]) {
        return res.status(400).send('Invalid post index');
      }
      
      // Update likeCount based on isLike value
      postData[postIndex].post.comments[commentIndex].likeCount += isLike ? -1 : 1;
      
      // Write updated data back to the file
      fs.writeFile(postFile, JSON.stringify(postData, null, 2), (writeErr) => {
        if (writeErr) {
          console.error('Error writing data:', writeErr);
          return res.status(500).send('Error writing data');
        }
        res.send('Post updated successfully');
      });
    } catch (parseErr) {
      console.error('Error parsing JSON data:', parseErr);
      res.status(500).send('Invalid JSON format');
    }
  });
});

app.patch('/api/update-reply-like', (req, res) => {
  const { postIndex, commentIndex,replyIndex, isLike } = req.body;
  
  fs.readFile(postFile, 'utf8', (err, data) => {
    if (err) {
      console.error('Error reading data:', err);
      return res.status(500).send('Error reading data');
    }

    try {
      const postData = JSON.parse(data);
      // Check if postIndex is valid
      if (!postData[postIndex] || !postData[postIndex].post) {
        return res.status(400).send('Invalid post index');
      }

      // Update likeCount based on isLike value
      postData[postIndex].post.comments[commentIndex].replies[replyIndex].likeCount += isLike ? -1 : 1;


      // Write updated data back to the file
      fs.writeFile(postFile, JSON.stringify(postData, null, 2), (writeErr) => {
        if (writeErr) {
          console.error('Error writing data:', writeErr);
          return res.status(500).send('Error writing data');
        }
        res.send('Post updated successfully');
      });
    } catch (parseErr) {
      console.error('Error parsing JSON data:', parseErr);
      res.status(500).send('Invalid JSON format');
    }
  });
});

app.patch('/api/add-comment', (req, res) => {
  const { postIndex, name, date, comment, likeCount, replies } = req.body;

  console.log(postIndex, name, date, comment, likeCount, replies);
  
  fs.readFile(postFile, 'utf8', (err, data) => {
    if (err) {
      console.error('Error reading data:', err);
      return res.status(500).send('Error reading data');
    }

    try {
      const postData = JSON.parse(data);
      
      // Check if postIndex is valid
      if (!postData[postIndex] || !postData[postIndex].post) {
        return res.status(400).send('Invalid post index');
      }

      // Create a new comment object
      const newComment = {
        name: name,
        date: date,
        comment: comment,
        likeCount: likeCount || 0, // Default likeCount to 0 if not provided
        replies: replies || [] // Default replies to an empty array if not provided
      };

      // Add the new comment to the post's comments array
      postData[postIndex].post.comments.push(newComment);

      // Write the updated data back to the file
      fs.writeFile(postFile, JSON.stringify(postData, null, 2), (writeErr) => {
        if (writeErr) {
          console.error('Error writing data:', writeErr);
          return res.status(500).send('Error writing data');
        }
        res.send('Comment added successfully');
      });
    } catch (parseErr) {
      console.error('Error parsing JSON data:', parseErr);
      res.status(500).send('Invalid JSON format');
    }
  });
});


// fetch user data
// Protected route to fetch user data
app.get("/api/user-login-access-token", authenticateToken, async (req, res) => {
  try {
    const [allusers] = await db.query("SELECT * FROM sk_customer_credentials");
    const userData = allusers.filter(user => user.user_customerID.trim() === req.user.customerID.trim());

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
app.post("/api/user", authenticateToken, async (req, res) => {
  const { userToken } = req.body;

  if (!userToken) {
    return res.status(400).json({ success: false, message: 'No auth token retrieved' });
  }

  let authDecode;
  try {
    authDecode = jwtDecode(userToken);
    
  } catch (error) {
    return res.status(400).json({ success: false, message: error.message });
  }
  
  try {
    const [allusers] = await db.query("SELECT * FROM sk_customer_credentials");
    const [allusersInfo] = await db.query("SELECT * FROM sk_customer_info");
    const [allusersAddress] = await db.query("SELECT * FROM sk_customer_address");
    const [allParticipantData] = await db.query("SELECT * FROM sk_participant_info");
    
    const userData = allusers.filter(user => user.user_customerID === authDecode.customerID);
    const cleanedUserData = userData.map(({ id, user_loginSession, user_password, ...rest }) => rest);
    const userInfo = allusersInfo.filter(user => user.user_customerID === authDecode.customerID)
    const cleanedUserInfo = userInfo.map(({ id, ...rest }) => rest)
    const userAddress = allusersAddress.filter(user => user.user_customerID === authDecode.customerID)
    const cleanedAddress = userAddress.map(({ id, user_customerID, ...rest }) => rest)
    const participantData = allParticipantData.filter(user => user.user_customerID === authDecode.customerID)
    const cleanedParticpantData = participantData.map(({ id, user_customerID, ...rest }) => rest)
   
    
    const userinfo = [{ ...cleanedUserData[0], ...cleanedUserInfo[0], ...cleanedAddress[0], ...cleanedParticpantData[0] }];
    


    if (userData.length > 0) {
      return res.status(200).json({ success: true, data: userinfo });
    } else {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
  } catch (error) {
    console.error('Database error:', error);
    return res.status(500).json({ success: false, message: 'Database connection failed' });
  }
});


// Login endpoint
app.post("/api/login", limiter, [
  body('username').notEmpty().withMessage('Username or email is required.'),
  body('password').notEmpty().withMessage('Password is required.')
], async (req, res) => {

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const errorMessages = errors.array().map(error => error.msg);
    return res.status(400).json({ success: false, message: errorMessages[0] });  // Return only the first error message
  }

  const { username, password, region } = req.body;

  // Check that `region` is provided
  if (!region) {
    return res.status(400).json({ success: false, message: 'Region is required.' });
  }

  // Generate login session
  const generatedSession = generateRandomString(20);
  const loginSession = 'sknms' + generatedSession + 'log';

  const filterRegion = "SELECT * FROM sk_customer_credentials WHERE user_region = ?"
  const [filterRegionResult] = await db.query(filterRegion, [region]);

  try {
    if (filterRegionResult.length === 0) {
      return res.status(404).json({ success: false, message: 'No users found' });     
    }

    // Prepare SQL query to find user by username or email
    const sql = "SELECT * FROM sk_customer_credentials WHERE BINARY user_username = ? OR BINARY user_email = ?";

    const [result] = await db.query(sql, [username, username]);
    
    // Check if user exists and password is correct
    if (result.length === 1) {
      const user = result.filter(user => user.user_region === region);
      const filteredUser = user[0]
      
      if (await bcrypt.compare(password, filteredUser.user_password)) {
        // Password matches, update login session
        const updateSessionSql = "UPDATE sk_customer_credentials SET user_loginSession = ?, user_activity = 'active' WHERE BINARY user_username = ?";
        const [updateResult] = await db.query(updateSessionSql, [loginSession, filteredUser.user_username]);
        
        const customerID = filteredUser.user_customerID
        
        if (updateResult.affectedRows > 0) {
          // Generate JWT token for the user
          const authToken = jwt.sign({ customerID }, jwtSecret, { expiresIn: "7d" });
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
      const errorMessages = errors.array().map(error => error.msg);
      
      return res.status(400).json({ success: false, message: errorMessages[0] });
    }

    const customerID = 'skms_' + generateRandomString(10);
    const { email, mobileno, username, password, referral,region } = req.body;

    let ref
    
    const usernameCheckSql = "SELECT * FROM sk_customer_credentials WHERE BINARY user_username = ?";
    const [usernameCheckResults] = await db.query(usernameCheckSql, [username]);
    if (usernameCheckResults.length > 0) {
      return res.status(400).json({ success: false, message: 'Username already exists' });
    }

    const emailCheckSql = "SELECT * FROM sk_customer_credentials WHERE BINARY user_email = ?";
    const [emailCheckResults] = await db.query(emailCheckSql, [email]);
    if (emailCheckResults.length > 0) {
      return res.status(400).json({ success: false, message: 'Email already exists' });
    }

    if (mobileno !== "no phone added") {
      const mobileCheckSql = "SELECT * FROM sk_customer_credentials WHERE user_mobileno = ?";
      const [mobileCheckResults] = await db.query(mobileCheckSql, [mobileno]);
      if (mobileCheckResults.length > 0) {
        return res.status(400).json({ success: false, message: 'Mobile number already exists' });
      }
    }

    
    if (referral !== "") {
      const referralCheckSql = "SELECT * FROM sk_participant_info WHERE user_participant_referral = ?";
      const [referralCheckResults] = await db.query(referralCheckSql, [referral]);
      if (referralCheckResults.length === 0) {
        return res.status(400).json({ success: false, message: 'Referral Code Does not exist' });
      }
    }

    if (referral === '') {
      ref = 'def'
    } else (
      ref = referral
    )

    const hash_pass = await bcrypt.hash(password, 10);
    const generatedSession = generateRandomString(10);
    const userRole = 'customer';
    const loginSession = 'sknms' + generatedSession + 'log';
    const activity = 'active';

    const insertSql = "INSERT INTO sk_customer_credentials (user_customerID, user_mobileno, user_email, user_username, user_password, user_role, user_referral,user_region, user_activity, user_loginSession) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    const [insertResult] = await db.query(insertSql, [customerID, mobileno, email, username, hash_pass, userRole, ref, region, activity, loginSession]);

    if (insertResult.affectedRows > 0) {

      const insertInfo = "INSERT INTO sk_customer_info (user_customerID) VALUES (?)";
      const [insertInfoResult] = await db.query(insertInfo, [customerID]);

      if (insertInfoResult.affectedRows > 0) {
        const authToken = jwt.sign({ customerID }, jwtSecret, { expiresIn: "7d" });
        return res.status(200).json({ success: true, message: 'Customer successfully registered', loginSession, token: authToken });
      } else {
        return res.status(500).json({ success: false, message: 'Error registering user' });
      }
    } else {
      return res.status(500).json({ success: false, message: 'Error registering user' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: 'Internal server error', error: error.message }); // Return specific error message
  }
});

// Updata endpoint
app.post("/api/update-user-data",authenticateToken, async (req,res) => {
  const {userData} = req.body

  if (!userData) {
    res.status(500).json({success:false, message: "No data retrieve"})
  }
  
  const customerID = userData.user_customerID

  const email = userData.user_email;
  const mobileno = userData.user_mobileno
  const firstName = userData.user_first_name;
  const lastName = userData.user_last_name;
  const gender = userData.user_gender;
  const bday = userData.user_birthday
  const username = userData.user_username
  const profession = userData.user_participant_profession
  const talent = userData.user_participant_talent
  const description = userData.user_participant_description
  const approval = userData.user_participant_approved
  
  try {
    const updateUsercred = `
      UPDATE sk_customer_credentials 
      SET user_email = ?, user_mobileno = ?, user_username = ?
      WHERE user_customerID = ?`;
    const [updateUsercredRes] = await db.query(updateUsercred, [email, mobileno,username, customerID]);

    if (updateUsercredRes.affectedRows > 0) {
      const updataUserInfo = `
      UPDATE sk_customer_info 
      SET user_first_name = ?, user_last_name = ?,user_gender = ? ,user_birthday = ?
      WHERE user_customerID = ?`;
      
      const [updateUserInfoRes] = await db.query(updataUserInfo, [firstName, lastName,gender,bday, customerID]);

      if (updateUserInfoRes.affectedRows > 0) {
        if (typeof talent === 'undefined') {
          return res.status(200).json({ success: true, message: "User data successfully updated" });
        } else {
          const updateParticipantInfo = `
          UPDATE sk_participant_info 
          SET user_participant_description = ?, user_participant_profession = ?, user_participant_talent = ? ,user_participant_approved = ?
          WHERE user_customerID = ?`;
          
          const [updateParticipantRes] = await db.query(updateParticipantInfo, [description, profession,talent,approval, customerID]);
          if (updateParticipantRes.affectedRows > 0) {
            return res.status(200).json({ success: true, message: "User data successfully updated" });
          }
          return res.status(200).json({ success: true, message: "User data successfully updated" });
        }
      } else {
        return res.status(500).json({ success: false, message: "User not found or no changes made" });
      }
    }
    return res.status(500).json({ success: false, message: "User not found or no changes made" });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Internal server error', error: error.message }); // Return specific error message
  }


})


app.post("/api/update-social-data",authenticateToken, async (req,res) => {
  const {socialLinks} = req.body
  
  if (!socialLinks) {
    res.status(500).json({success:false, message: "No data retrieve"})
  }
  
  const customerID = socialLinks.customerID
  const facebook = socialLinks.facebook
  const instagram = socialLinks.instagram
  const tiktok = socialLinks.tiktok

  try {

    const [checkRegisteredID] = await db.query('SELECT * FROM sk_participant_info WHERE BINARY user_customerID = ?',[customerID]);
    console.log(checkRegisteredID[0]);
    
    if (checkRegisteredID.length === 0) {
      const insertParticipant = "INSERT INTO sk_participant_info (user_customerID, user_participant_facebook, user_participant_instagram, user_participant_tiktok) VALUES (?, ?, ?, ?)";
      const [insertParticipantRes] = await db.query(insertParticipant, [customerID, facebook, instagram, tiktok]);
      if (insertParticipantRes.affectedRows > 0) {
        return res.status(200).json({ success: true, message: "Participant Data Added successfully" });
      }
    } else {
      const updateParticipant = 'UPDATE sk_participant_info SET user_participant_facebook = ?, user_participant_instagram = ?, user_participant_tiktok = ? WHERE user_customerID = ?';
      const [updateParticipantRes] = await db.query(updateParticipant, [facebook, instagram, tiktok, customerID]);
      
      if (updateParticipantRes.affectedRows > 0) {
        return res.status(200).json({ success: true, message: "Participant Socials successfully updated" });
      }
    }
    
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Internal server error', error: error.message }); // Return specific error message
  }


})

// Logout endpoint
app.post("/api/logout", authenticateToken, async (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ success: false, message: 'Username is required' });
  }

  try {
    // Use the connection pool to query the database
    const connection = await db.getConnection(); 

    try {
      // Check if the user exists
      const [userResult] = await db.query(
        'SELECT * FROM sk_customer_credentials WHERE BINARY user_username = ?',
        [username]
      );

      if (userResult.length === 1) {
        // Update user activity to inactive and clear login session
        const updateSql = 'UPDATE sk_customer_credentials SET user_loginSession = "", user_activity = "inactive" WHERE user_username = ?';
        const [updateResult] = await db.query(updateSql, [username]);

        if (updateResult.affectedRows > 0) {
          return res.status(200).json({ success: true, message: 'Logout successful' });
        } else {
          return res.status(500).json({ success: false, message: 'Error updating user status' });
        }
      } else {
        return res.status(404).json({ success: false, message: 'User not found' });
      }
    } catch {
      return res.status(500).json({ success: false, message: 'Database connection failed' });
    }

  } catch (error) {
    console.error('Database error:', error);
    return res.status(500).json({ success: false, message: 'Database connection failed' });
  }
});

// update Address 
app.post('/api/update-address',authenticateToken, async (req,res) => {
  const {addressData} = req.body;
  
  if (!addressData) {
    return res.status(500).json({ success: false, message: "No data received"})
  }

  try {
    const customerID = addressData.customerID
    const country = addressData.country
    const addressLabel = addressData.addressLabel
    const city = addressData.city
    const district = addressData.district
    const houseNumber = addressData.houseNumber
    const postalCode = addressData.postalCode
    const region = addressData.region
    const state = addressData.state
    const street = addressData.street
    const area = addressData.area

    const [checkCustomerAddress] = await db.query(
      'SELECT * FROM sk_customer_address WHERE user_customerID = ?',
      [customerID]
    );

    if (checkCustomerAddress.length > 0) {
      const updateAddress = "UPDATE sk_customer_address SET user_country = ?, user_state = ?, user_area = ?, user_region = ?,user_district = ?, user_city = ?, user_postal_code = ?, user_street = ?, user_houseNo = ?, user_address_label = ? WHERE user_customerID = ?"

      const [updateRes] = await db.query(updateAddress, [country, state, area, region, district, city, postalCode, street, houseNumber, addressLabel, customerID]);

      if (updateRes.affectedRows > 0) {
        return res.status(200).json({ success: true, message: 'Successfull updated the address' });
      }
    } else if (checkCustomerAddress.length === 0) {
      const insertAddress = "INSERT INTO sk_customer_address (user_country, user_state, user_area, user_region, user_district, user_city, user_postal_code, user_street, user_houseNo, user_address_label, user_customerID) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
      const [insertAddressRes] = await db.query(insertAddress, [country, state,area, region, district, city, postalCode, street, houseNumber, addressLabel, customerID]);
      
      if (insertAddressRes.affectedRows > 0) {
        return res.status(200).json({ success: true, message: 'Successfull Added the address' });
      }
    } else {
      return res.status(500).json({success:false, message : "unknown Internal Server Error"})
    }
  
  } catch (error) {
    console.log(error);
    
  }
})

app.post("/api/upload-profile-picture",authenticateToken, upload.single("profilePic"), async (req, res) => {
  const profileFile = req.file;
  const customerID = req.body.customerID
  const imgName = customerID + profileFile.originalname
  
  if (!profileFile) {
    return res.status(400).send("No file uploaded.");
  }

  const formData = new FormData();
  formData.append("profilePic", profileFile.buffer, { filename: imgName, contentType: profileFile.mimetype });

  try {
    const response = await axios.post("https://2wave.io/skinmiso/php/upload-customer-profile.php", formData, {
      headers: {
        ...formData.getHeaders(), // Use getHeaders here for axios compatibility
      },
    });
    
    if (response.data.status === 'success') {

      const updateAddress = "UPDATE sk_customer_info SET user_profile_pic = ? WHERE user_customerID = ?"

      const [updateRes] = await db.query(updateAddress, [imgName, customerID]);
      
      if (updateRes.affectedRows > 0) {
        return res.status(200).json({ success: true, message: 'Successfull Updated Profile ' });
      } else {
        console.log('error updating data');
      }
    }
  } catch (error) {
    return res.status(500).json({success:false, message : "unknown Internal Server Error"})
  }
});

app.post("/api/upload-cover-photo",authenticateToken, upload.single("coverPhoto"), async (req, res) => {
  const coverFile = req.file;
  const customerID = req.body.customerID
  const imgName = customerID + coverFile.originalname
  console.log(coverFile, customerID);
  
  if (!coverFile) {
    return res.status(400).send("No file uploaded.");
  }

  const formData = new FormData();
  formData.append("coverPhoto", coverFile.buffer, { filename: imgName, contentType: coverFile.mimetype });

  try {
    const response = await axios.post("https://2wave.io/skinmiso/php/upload-cover-photo.php", formData, {
      headers: {
        ...formData.getHeaders(), // Use getHeaders here for axios compatibility
      },
    });
    
    if (response.data.status === 'success') {

      const updateAddress = "UPDATE sk_customer_info SET user_cover_photo = ? WHERE user_customerID = ?"

      const [updateRes] = await db.query(updateAddress, [imgName, customerID]);
      
      if (updateRes.affectedRows > 0) {
        return res.status(200).json({ success: true, message: 'Successfull Updated Cover Photo ' });
      } else {
        console.log('error updating data');
      }
    }
  } catch (error) {
    return res.status(500).json({success:false, message : "unknown Internal Server Error"})
  }
});


app.post("/api/upload-facecard-picture", authenticateToken, upload.fields([
  { name: "cardImage", maxCount: 1 },
  { name: "faceCard1", maxCount: 1 },
  { name: "faceCard2", maxCount: 1 }
]), async (req, res) => {
  const customerID = req.body.customerID;
  // Extract files from the request
  const cardImageFile = req.files["cardImage"] ? req.files["cardImage"][0] : null;
  const faceCard1File = req.files["faceCard1"] ? req.files["faceCard1"][0] : null;
  const faceCard2File = req.files["faceCard2"] ? req.files["faceCard2"][0] : null;

  // Check if any required file is missing
  if (!cardImageFile || !faceCard1File || !faceCard2File) {
    return res.status(400).send("Missing one or more files.");
  }

  // Create FormData to send to the next endpoint
  const formData = new FormData();
  formData.append("cardImage", cardImageFile.buffer, { filename: customerID + cardImageFile.originalname, contentType: cardImageFile.mimetype });
  formData.append("faceCard1", faceCard1File.buffer, { filename: customerID + faceCard1File.originalname, contentType: faceCard1File.mimetype });
  formData.append("faceCard2", faceCard2File.buffer, { filename: customerID + faceCard2File.originalname, contentType: faceCard2File.mimetype });

  try {
    // Send the form data to another server (PHP server)
    const response = await axios.post("https://2wave.io/skinmiso/php/upload-facecards.php", formData, {
      headers: {
        ...formData.getHeaders(), // Get correct headers for form data
      },
    });

    // If successful, update database
    if (response.data.status === "success") {
      const updateQuery = `UPDATE sk_participant_info SET user_participant_card_img = ?, user_participant_facecard_1 = ?, user_participant_facecard_2 = ? WHERE user_customerID = ?`;

      const [updateRes] = await db.query(updateQuery, [
        customerID + cardImageFile.originalname,
        customerID + faceCard1File.originalname,
        customerID + faceCard2File.originalname,
        customerID,
      ]);
      

      if (updateRes.affectedRows > 0) {
        return res.status(200).json({ success: true, message: "Successfully updated facecard pictures." });
      } else {
        return res.status(500).json({ success: false, message: "Error updating database" });
      }
    } else {
      return res.status(500).json({ success: false, message: "Error uploading to PHP server" });
    }
  } catch (error) {
    return res.status(500).json({ success: false, message: "Unknown internal server error" });
  }
});


app.post('/api/participant-list', async (req, res) => {
  const { region } = req.body;

  try {
    const [alldataUsers] = await db.query(`
      SELECT 
          sk_participant_info.user_customerID,
          sk_participant_info.*, 
          sk_customer_info.*,
          sk_customer_credentials.*
      FROM sk_participant_info
      INNER JOIN sk_customer_info 
          ON sk_participant_info.user_customerID = sk_customer_info.user_customerID COLLATE utf8mb4_unicode_ci
      INNER JOIN sk_customer_credentials 
          ON sk_participant_info.user_customerID = sk_customer_credentials.user_customerID COLLATE utf8mb4_unicode_ci
    `);

    const approvedUsers = alldataUsers.filter(users => users.user_region === region)

    const cleanedUser = approvedUsers.map(({ 
      id, user_password, user_email, user_mobileno, user_role, user_referral, user_region, 
      user_fb_connected, user_google_connected, user_loginSession,
      ...rest 
    }) => rest);
    
    if (cleanedUser.length > 0) {
      return res.status(200).json({ success: true, users: cleanedUser });
    } else {
      return res.status(404).json({ success: false, message: "No users found for the specified region" });
    }
  } catch (error) {
    return res.status(500).json({ success: false, message: "Unknown internal server error", error: error.message });
  }
});

app.post('/api/participant-gt-post', async (req, res) => {
  const { region } = req.body;

  try {
    const [alldataUsers] = await db.query(`
      SELECT 
          sk_customer_credentials.user_username,
          sk_customer_credentials.user_region,
          sk_participant_links.*
      FROM sk_participant_links
      INNER JOIN sk_customer_credentials 
          ON sk_participant_links.user_customerID = sk_customer_credentials.user_customerID COLLATE utf8mb4_unicode_ci
    `);

    const approvedUsers = alldataUsers.filter(users => users.user_region === region);
      
    const cleanedUser = await Promise.all(approvedUsers.map(async (user) => {
      const { user_participant_link } = user; 

      try {
        const { data: html } = await axios.get(user_participant_link);
        const $ = cheerio.load(html);
        
        
        const title = $('title').text() || "No title found";
        const description = $('meta[name="description"]').attr('content') || "No description found";
        const image = $('meta[property="og:image"]').attr('content') || "No image found";

        return {
          ...user,
          title,
          description,
          image
        };
      } catch (error) {
        console.error(`Error fetching data for URL ${user_participant_link}:`, error.message);
        return {
          ...user,
          title: "No title found",
          description: "No description found",
          image: "No image found"
        };
      }
    }));
    
    if (cleanedUser.length > 0) {
      return res.status(200).json({ success: true, users: cleanedUser });
    } else {
      return res.status(404).json({ success: false, message: "No users found for the specified region" });
    }
  } catch (error) {
    return res.status(500).json({ success: false, message: "Unknown internal server error", error: error.message });
  }
});

app.post('/api/all-reviews', async (req,res) => {
  const {region} = req.body

  const [allreviews] = await db.query(`
    SELECT 
      sk_product_reviews.sm_customerID,
      sk_product_reviews.*,
      sk_customer_credentials.*,
      sk_customer_info.*
    FROM sk_product_reviews
    INNER JOIN sk_customer_credentials 
      ON sk_product_reviews.sm_customerID = sk_customer_credentials.user_customerID COLLATE utf8mb4_unicode_ci
    INNER JOIN sk_customer_info 
      ON sk_product_reviews.sm_customerID = sk_customer_info.user_customerID COLLATE utf8mb4_unicode_ci
  `);

  const filterUsers = allreviews.filter(users => users.user_region === region)

  const cleanedUser = filterUsers.map(({ 
    id,sm_customerID,user_customerID, user_password, user_email, user_mobileno, user_role, user_referral, user_region, 
    user_fb_connected, user_google_connected, user_loginSession,
    ...rest 
  }) => rest);
  
  if (cleanedUser.length > 0) {
    return res.status(200).json({ success: true , reviews: cleanedUser, message: 'All reviews fetch' })
  } else {
    return res.status(500).json({ success: false , message: 'Internal Server Error' })
  }

})
app.post('/api/add-product-review', authenticateToken, async (req,res) => {
  const { productName, productID, customerID, review, reviewImgName } = req.body
  
  if (!customerID) {
    return res.status(500).json({ success: false, message: 'invalid req, customer require'})
  }

  const reviewID = "sm_review_" + generateRandomString(20)

  try {
    
    const inserReview = "INSERT INTO sk_product_reviews (sm_review_id, sm_product_name,sm_productID, sm_customerID, sm_review, sm_review_img ) VALUES (?, ?, ?, ?, ?)";
    const [insertReviewRes] = await db.query(inserReview, [reviewID, productName,productID, customerID, review, reviewImgName]);

    if (insertReviewRes.affectedRows > 0) {
      return res.status(200).json({ success:true, message: "Review successfully added"})
    } else {
      return res.status(500).json({ success: true, message: "Internal server Error"})
    }

  } catch (error) {
    
  }

})


app.post("/api/upload-review-picture",authenticateToken, upload.single("reviewImage"), async (req, res) => {
  const reviewFile = req.file;
  const customerID = req.body.customerID
  const imgName = customerID + reviewFile.originalname
  
  if (!reviewFile) {
    return res.status(400).send("No file uploaded.");
  }

  const formData = new FormData();
  formData.append("reviewImage", reviewFile.buffer, { filename: imgName, contentType: reviewFile.mimetype });

  try {
    const response = await axios.post("https://2wave.io/skinmiso/php/upload-customer-profile.php", formData, {
      headers: {
        ...formData.getHeaders(), // Use getHeaders here for axios compatibility
      },
    });
    
    if (response.data.status === 'success') {
      
      return res.status(200).json({ success: true, message: 'Successfull Uploaded Review Image ' });
     
    }
  } catch (error) {
    return res.status(500).json({success:false, message : "unknown Internal Server Error"})
  }
});




const forgotPassCode = (length) => {
  const charset = "1234567890";
  let result = "";
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * charset.length);
    result += charset.charAt(randomIndex);
  }
  return result;
};

// verify user
app.post('/api/verify-email', async (req, res) => {
  const { to } = req.body;
  
  if (to.length > 0) {
    
    const codePass = forgotPassCode(6)
    const subject = "Verify Email";
    const htmlContent = renderToStaticMarkup(
      React.createElement(Confirmation, { codePass })
    );

    
    const jwtCode = jwt.sign({ codePass }, jwtSecret, { expiresIn: "7d" });

    let transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false, // true for 465, false for other ports
      auth: {
        user: 'skinmisocanada@gmail.com',
        pass: 'zknk mxbf qxrs qfyp',
      },
      tls: {
        ciphers: 'SSLv3',
      }
    });
    try {
      let info = transporter.sendMail({
        from: '"Skinmiso Canada Support" <skinmisocanada@gmail.com>', // sender address
        to: to,
        subject: subject,
        html: htmlContent, // use HTML version of the email
      });
      
      res.status(200).json({ message: 'Email sent successfully', jtdcd: jwtCode});
    } catch (error) {
      console.error('Error sending email:', error);
      res.status(500).send('Error sending email');
    }
  } else {
    res.json({ message: 'Email not found'});
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
        const customerID = emailCheckResults[0].user_customerID;
        
        const connected = emailCheckResults[0].user_fb_connected;

        if (connected === 'connected') {
          const authToken = jwt.sign({ customerID }, jwtSecret, { expiresIn: "7d" });
          // Push to login
          return res.status(200).json({ success: true, message: "Customer Login successfully", token: authToken, loginSession,facebook: connected});
        } else {
          // Update Facebook connection status
          const updateData = "UPDATE sk_customer_credentials SET user_fb_connected = ? WHERE user_customerID = ?";
          const [updateDataResult] = await db.query(updateData, [fbConnected, customerID]);

          if (updateDataResult.affectedRows > 0) {
            // Insert Facebook info if update was successful
            const insertFBinfo = "INSERT INTO sk_customer_facebook (user_customerID, user_facebookID) VALUES (?, ?)";
            const [insertFBData] = await db.query(insertFBinfo, [customerID, fbID]);
            
            if (insertFBData.affectedRows > 0) {
              const authToken = jwt.sign({ customerID }, jwtSecret, { expiresIn: "7d" });
              return res.status(200).json({ success: true, message: "Customer Login successfully", token: authToken, loginSession, customerID: customerID });
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
          const authToken = jwt.sign({ customerID }, jwtSecret, { expiresIn: "7d" });
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
app.post('/api/google-signin', async (req, res) => {
  const { data,region } = req.body;

  const decoded = jwtDecode(data)

  if (decoded) {
    try {
      const userRole = 'customer';
      const fbConnected = 'connected';
      const customerID = 'skms_' + generateRandomString(10);
      const email = decoded.email;
      const username = 'skms_user' + generateRandomString(10);
      const mobileno = 'no phone added';
      const hash_pass = '';
      const generatedSession = generateRandomString(10);
      const loginSession = 'sknms' + generatedSession + 'log';
      const activity = 'active';

      const emailCheckSql = "SELECT * FROM sk_customer_credentials WHERE user_email = ?";
      const [emailCheckResults] = await db.query(emailCheckSql, [email]);

      if (emailCheckResults.length > 0) {
        const customerID = emailCheckResults[0].user_customerID;
        
        const connected = emailCheckResults[0].user_google_connected;

        if (connected === 'connected') {
          const authToken = jwt.sign({ customerID }, jwtSecret, { expiresIn: "7d" });
          // Push to login
          return res.status(200).json({ success: true, message: "Customer Login successfully", token: authToken, loginSession,google: connected});
        } else {
          // Update Facebook connection status
          const updateData = "UPDATE sk_customer_credentials SET user_google_connected = ? WHERE user_customerID = ?";
          const [updateDataResult] = await db.query(updateData, [fbConnected, customerID]);

          if (updateDataResult.affectedRows > 0) {

            const authToken = jwt.sign({ customerID }, jwtSecret, { expiresIn: "7d" });
            return res.status(200).json({ success: true, message: "Customer Login successfully", token: authToken, loginSession, customerID: customerID });

          } else {
            return res.status(500).json({ success: false, message: 'Error updating customer credentials' });
          }
        }
      }

      // If user does not exist, insert new user data
      const insertSql = "INSERT INTO sk_customer_credentials (user_customerID, user_mobileno, user_email, user_username, user_password, user_role, user_google_connected, user_activity, user_loginSession) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
      const [insertResult] = await db.query(insertSql, [customerID, mobileno, email, username, hash_pass, userRole, fbConnected, activity, loginSession]);

      if (insertResult.affectedRows > 0) {
        const authToken = jwt.sign({ customerID }, jwtSecret, { expiresIn: "7d" });
        return res.status(200).json({ success: true, message: "Customer registered successfully", token: authToken, loginSession});
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

// products
// products names only
app.get("/api/products", async (req, res) => {

  try {
    const [allPrdNames] = await db.query("SELECT * FROM sk_products");
    const cleanedPrdnames = allPrdNames.map(prd => {
      const { id, ...rest } = prd;
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

    // Fetch the specific product by name
    const [productResults] = await db.query('SELECT * FROM sk_products WHERE sm_product_name = ?', [productName]);
    if (productResults.length > 0) {
      products[productName] = productResults[0];
    }
    

    // Fetch associated images
    const [imgsResults] = await db.query('SELECT * FROM sk_product_imgs WHERE sm_product_name = ?', [productName]);
    if (imgsResults.length > 0) {
      products[productName].images = imgsResults[0];
    }

    // Fetch associated info
    const [infoResults] = await db.query('SELECT * FROM sk_product_info WHERE sm_product_name = ?', [productName]);
    if (infoResults.length > 0) {
      products[productName].info = infoResults[0];
    }

    // Fetch associated shorts
    const [shortsResults] = await db.query('SELECT * FROM sk_product_shorts WHERE sm_product_name = ?', [productName]);
    if (shortsResults.length > 0) {
      products[productName].shorts = shortsResults[0];
    }
    
    res.status(200).json(products[productName]);
  } catch (err) {
    console.error('Error fetching product info:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/all-products', async (req,res) => {
  try {

    const [productList] = await db.query(`
      SELECT 
          sk_products.sm_productID, 
          sk_products.sm_product_category, 
          sk_product_info.*, 
          sk_product_imgs.*
      FROM sk_products
      INNER JOIN sk_product_info 
          ON sk_products.sm_productID = sk_product_info.sm_productID
      INNER JOIN sk_product_imgs 
          ON sk_products.sm_productID = sk_product_imgs.sm_productID;
    `);

    if (productList.length > 0) {
      return res.status(200).json({ success: true, productData: productList })
    } else {
      return res.status(500).json({ success:false, message: "Internal Server Error"})
    }

  } catch (error) {
    console.log(error);
    
  }
})


app.get('/api/all-products-banner', async (req,res) => {
  try {
    const [allPrdBanners] = await db.query(`SELECT * FROM sk_banners_images`);
    
    res.status(200).json(allPrdBanners)
  } catch (error) {
    console.log(error);
  }
})


app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
