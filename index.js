const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const express = require('express');
const bcrypt = require('bcrypt');
const mysql = require('mysql');
const path = require('path');
const fs = require('fs');
const app = express();
const port = 3000;
require("dotenv").config();

const saltrounds = 10;

const connection = mysql.createConnection({
  host: process.env.MYSQL,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DB,
});

connection.connect((err) => {
  if (err) {
    console.log('Error connecting to Db', err.stack);
    return;
  }

  console.log('Connection with Database established');
});

//MIDDLEWARE

app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ROUTES
app.get('/', (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    res.sendFile(__dirname + '/public/index.html');
    return;
  }
  jwt.verify(token, 'sussy', (err) => {
    if (err) {
      res.status(401).json({ error: 'Invalid token' });
      return;
    } else {
      res.redirect('/loggedin');
    }
  });
});

app.get('/register', (req, res) => {
  res.sendFile(__dirname + '/public/register.html');
});

app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/public/login.html');
});

app.get('/loggedin', (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    res.redirect('/');
    return;
  }
  jwt.verify(token, 'sussy', (err) => {
    if (err) {
      res.status(401).json({ error: 'Invalid token' });
      return;
    } else {
      return res.sendFile(__dirname + '/public/loggedin.html');
    }
  });
});


// REGISTER POST REQUEST

app.post('/register', async(req, res) => {
  const userData = req.body;

  //console.log('Request body: ', userData);
  const hashedPassword = await bcrypt.hash(userData.password, saltrounds);

  const check = `SELECT * FROM users WHERE username = ?`;
  const checkValues = [userData.username];
  const sql = `INSERT INTO users (username, password) VALUES (?, ?)`;
  const values = [userData.username, hashedPassword];
    
  connection.query(check, checkValues, (err, result) => {
    if (err) {
      console.error('Error fetching record:', err);
      res.status(500).json({ error: 'Failed to fetch user' });
      return;
    }
    if (result.length > 0) {
      res.status(400).json({ error: 'Username already exists' });
      return;
    } else {
      connection.query(sql, values, (err, result) => {
        if (err) {
          console.error('Error inserting record:', err);
          res.status(500).json({ error: 'Failed to insert user' });
          return;
        }
        console.log('User inserted successfully');
        res.redirect('/login');
      });
    }
  });


});

// LOGIN POST REQUEST

app.post('/login', async(req, res) => {
  const userData = req.body;

  const sql = `SELECT * FROM users WHERE username = ?`;
  const values = [userData.username];

  connection.query(sql, values, async(err, queryRes) => {
    if (err) {
      console.error('Error fetching record:', err);
      res.status(500).json({ error: 'Failed to fetch user' });
      return;
    }
    
    if (queryRes.length === 0) {
      res.status(401).json({ error: 'Invalid username or password' });
      return;
    }

    const user = queryRes[0];
    const passwordMatch = await bcrypt.compare(userData.password, user.password);
  
    if (!passwordMatch) {
      res.status(401).json({ error: 'Invalid username or password' });
      return;
    }
    // If the user has a valid token, they instantly get redirected to the loggedin page

    const token = jwt.sign({ username: user.username, password: user.password }, 'sussy');
    jwt.verify(token, 'sussy', (err, decoded) => {
      if (err) {
        console.error('Error verifying token:', err);
        res.status(500).json({ error: 'Failed to verify token' });
        return;
      } else {
        res.cookie('token', token, { httpOnly: true });
        res.redirect('/loggedin');
      }
    });  
  });
  });




app.use(express.static(path.join(__dirname, 'public')));

app.listen(port, () => {
  console.log(`myApp listening on port ${port}`);
});
