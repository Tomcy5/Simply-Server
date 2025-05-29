require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const UserModel = require('./models/UserModel');
const PostModel = require('./models/PostModel');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();

// ✅ Ensure 'public/Images' directory exists
const uploadPath = path.join(__dirname, 'public/Images');
if (!fs.existsSync(uploadPath)) {
  fs.mkdirSync(uploadPath, { recursive: true });
}

// ✅ Middleware
app.use(express.json());
app.use(express.static('public'));
app.use(cors({
  origin: ["http://localhost:3000", "https://simply-client.vercel.app"],
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));
app.use(cookieParser());

// ✅ Environment Variables
const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

// ✅ MongoDB Connection
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// ✅ Auth Middleware
const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.json("token is not available");

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.json("wrong token");
    req.email = decoded.email;
    req.name = decoded.name;
    next();
  });
};

// ✅ Multer Config
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/Images');
  },
  filename: (req, file, cb) => {
    cb(null, file.fieldname + "_" + Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// ✅ Routes

// Register
app.post('/', (req, res) => {
  const { name, email, password } = req.body;
  bcrypt.hash(password, 10)
    .then(hash => {
      UserModel.create({ name, email, password: hash })
        .then(result => res.json(result))
        .catch(err => res.json(err));
    })
    .catch(err => res.json(err));
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await UserModel.findOne({ email });
    if (!user) return res.json({ msg: "Invalid user" });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.json({ msg: "Invalid password" });

    const token = jwt.sign(
      { email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000
    });

    res.json({ Status: "login success", role: user.role });

  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Internal server error" });
  }
});

// Home
app.get('/home', verifyUser, (req, res) => {
  res.json({ email: req.email, name: req.name });
});

// Add Post
app.post('/addpost', verifyUser, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ msg: "No file uploaded" });
  }

  PostModel.create({
    title: req.body.title,
    description: req.body.description,
    file: req.file.filename
  })
    .then(() => res.json("post added success"))
    .catch(err => res.json(err));
});

// Get All Posts
app.get('/getposts', (req, res) => {
  PostModel.find()
    .then(posts => res.json(posts))
    .catch(err => res.json(err));
});

// View Post
app.get('/viewpost/:id', (req, res) => {
  PostModel.findById(req.params.id)
    .then(result => res.json(result))
    .catch(err => console.log(err));
});

// Edit Post
app.put('/editpost/:id', (req, res) => {
  PostModel.findByIdAndUpdate(req.params.id, {
    title: req.body.title,
    description: req.body.description
  })
    .then(() => res.json("post updated"))
    .catch(err => console.log(err));
});

// Delete Post
app.delete('/deletepost/:id', (req, res) => {
  PostModel.findByIdAndDelete(req.params.id)
    .then(() => res.json("post deleted"))
    .catch(err => console.log(err));
});

// Get All Users
app.get('/getalluserdata', (req, res) => {
  UserModel.find()
    .then(result => res.json(result))
    .catch(err => res.json(err));
});

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.json("cookie cleared");
});

// Error Handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ msg: "Something broke!" });
});

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
