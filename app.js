var express = require('express');
const mysql = require('mysql')
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'accredian'
})

connection.connect()

var app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors());

app.get('/', function (req, res) {
  res.send('Hello World!');
});

app.post('/register', async (req, res) => {
  const { username, email, password, cpassword } = req.body;

  if (!username || !email || !password || !cpassword) {
    return res.status(422).send("Missing required fields");
  }

  if (password === cpassword) {
    connection.query('SELECT * FROM users WHERE email = ?', [email], async (error, results) => {
      if (error) {
        return res.status(400).send(`Bad request: ${error.message}`);
      } else {
        if (results.length === 0) {
          try {
            const hashedPassword = await bcrypt.hash(password, 10);
            connection.query('INSERT INTO users VALUES (?, ?, ?)', [username, email, hashedPassword], (error) => {
              if (error) {
                return res.status(400).send(`Bad request: ${error.message}`);
              } else {
                return res.status(201).send('User created successfully');
              }
            });
          } catch (hashError) {
            return res.status(400).send(`Bad request: ${hashError.message}`);
          }
        } else {
          return res.status(409).send("Email already taken");
        }
      }
    });
  } else {
    res.status(422).send("Password does not match");
  }
});

app.post('/login', async (req, res) => {
  const { usernameOrEmail, password } = req.body;

  if (!usernameOrEmail || !password) {
    return res.status(400).send('Username/Email and password are required.');
  }

  const isEmail = usernameOrEmail.includes('@');

  let query = '';
  let queryParams = [];
  if (isEmail) {
    query = 'SELECT * FROM users WHERE email = ?';
    queryParams = [usernameOrEmail];
  } else {
    query = 'SELECT * FROM users WHERE username = ?';
    queryParams = [usernameOrEmail];
  }

  connection.query(query, queryParams, (error, results) => {
    if (error) {
      return res.status(400).send(`Bad request: ${error.message}`);
    }
    if (results.length === 0) {
      return res.status(404).send('User does not exist. Please register!');
    }
    const user = results[0]; 
    bcrypt.compare(password, user.password, (bcryptError, passwordMatch) => {
      if (bcryptError) {
        return res.status(500).send('Internal server error');
      }
      if (!passwordMatch) {
        return res.status(401).send('Invalid password');
      }
      res.status(200).json(user.username);
    });
  });
});


app.listen(3000, function () {
  console.log('Example app listening on port 3000!');
});
