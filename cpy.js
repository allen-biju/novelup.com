const express = require('express');
const cors = require('cors');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const stripe = require('stripe')('your-stripe-secret-key');
const http = require('http');
const socketIo = require('socket.io');
const { Sequelize, DataTypes, Op } = require('sequelize');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads/profile_pictures', express.static(path.join(__dirname, 'uploads/profile_pictures')));
app.use('/uploads/book_images', express.static(path.join(__dirname, 'uploads/book_images')));


// Ensure directories exist
const ensureDirExists = (dir) => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
};
ensureDirExists('uploads/profile_pictures');
ensureDirExists('uploads/book_images');

// Multer Storage for Profile Pictures
const profileStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/profile_pictures/');
    },
    filename: (req, file, cb) => {
        cb(null, `profile-${Date.now()}${path.extname(file.originalname)}`);
    }
});
const profileUpload = multer({ storage: profileStorage });

// Multer Storage for Book Cover Images
const bookStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/book_images/');
    },
    filename: (req, file, cb) => {
        cb(null, `book-${Date.now()}-${file.originalname}`);
    }
});
const bookUpload = multer({ storage: bookStorage });


// Database Connection
const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
    host: process.env.DB_HOST,
    dialect: 'mysql',
});

sequelize.authenticate()
    .then(() => console.log('MySQL Connected'))
    .catch(err => console.log('Error: ' + err));

// User Model
const User = sequelize.define('User', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    firstName: { type: DataTypes.STRING, allowNull: false },
    lastName: { type: DataTypes.STRING, allowNull: false },
    username: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
        set(value) {
            this.setDataValue('username', `${this.firstName}.${this.lastName}`.toLowerCase());
        }
    },
    email: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: false },
    profileImage: { type: DataTypes.STRING, allowNull: true },
    phoneNumber: { type: DataTypes.STRING, allowNull: true, unique: true },
    dateOfBirth: { type: DataTypes.DATE, allowNull: false },
}, { timestamps: false });

// Book Model
const Book = sequelize.define('Book', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    title: { type: DataTypes.STRING, allowNull: false },
    author: { type: DataTypes.STRING, allowNull: false },
    language: { type: DataTypes.STRING, allowNull: false },
    type: { type: DataTypes.STRING, allowNull: false },
    description: { type: DataTypes.TEXT, allowNull: true },
    coverImages: { type: DataTypes.JSON, allowNull: true },
    available: { type: DataTypes.BOOLEAN, defaultValue: true },
    rentPrice: { type: DataTypes.FLOAT, allowNull: false },
    userId: { type: DataTypes.INTEGER, allowNull: false },
}, { timestamps: false });

// Rental Model
const Rental = sequelize.define('Rental', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    userId: { type: DataTypes.INTEGER, allowNull: false },
    bookId: { type: DataTypes.INTEGER, allowNull: false },
    rentalDate: { type: DataTypes.DATE, allowNull: false },
    returnDate: { type: DataTypes.DATE, allowNull: false },
    rentalDuration: { type: DataTypes.INTEGER, allowNull: false }, // Duration in days
    totalPrice: { type: DataTypes.FLOAT, allowNull: false },
    pickupLocation: { type: DataTypes.STRING, allowNull: false, defaultValue: 'College of Engineering Vadakara Library' },
    confirmed: { type: DataTypes.BOOLEAN, defaultValue: false },
}, { timestamps: false });

User.hasMany(Book, { foreignKey: 'userId' });
User.hasMany(Rental, { foreignKey: 'userId' });
Book.hasMany(Rental, { foreignKey: 'bookId' });
Book.belongsTo(User, { foreignKey: 'userId' });
Rental.belongsTo(User, { foreignKey: 'userId' });
Rental.belongsTo(Book, { foreignKey: 'bookId' });

sequelize.sync();

// Middleware to Authenticate Users
const authenticateUser = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    try {
        const decoded = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(400).json({ error: 'Invalid token' });
    }
};

// Upload Book
app.post('/upload-book', authenticateUser, bookUpload.array('coverImages', 5), async (req, res) => {
    try {
        const { title, author, language, type, description, rentPrice } = req.body;
        const coverImages = req.files.map(file => file.path);
        const book = await Book.create({
            title,
            author,
            language,
            type,
            description,
            coverImages,
            rentPrice,
            userId: req.user.id,
        });
        io.emit('newBook', book); // Emit event to update books section in frontend
        res.status(201).json({ message: 'Book uploaded successfully', book });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Fetch All Books
app.get('/books', async (req, res) => {
    try {
        const books = await Book.findAll({ include: [{ model: User, attributes: ['firstName', 'lastName', 'username', 'profileImage'] }] });
        res.json(books);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// Fetch All Users
app.get('/users/:id', async (req, res) => {
    try {
        const user = await User.findOne({
            where: { id: req.params.id },
            attributes: ['id', 'firstName', 'lastName', 'username', 'email', 'profileImage']
        });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json(user);
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({
            where: {
                [Op.or]: [{ username }, { email: username }] // Check both username and email
            }
        });

        if (!user) return res.status(400).json({ error: "User not found" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

        const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, user });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Default profile image path
const DEFAULT_PROFILE_IMAGE = "uploads/default.jpg"; // Ensure this default image exists in the uploads folder

app.post('/register', profileUpload.single('profileImage'), async (req, res) => {
    console.log("Received body:", req.body);
    console.log("Uploaded file:", req.file);
    const { firstName, lastName, email, phoneNumber, dateOfBirth, password } = req.body;

    if (!req.file) {
        console.log("No file received!");
    }

    try {
        if (!email && !phoneNumber) {
            return res.status(400).json({ error: "Either Email or Phone Number is required" });
        }

        const cleanedEmail = email ? email.trim().toLowerCase() : null;
        const cleanedPhone = phoneNumber && phoneNumber.trim().toLowerCase() !== "null" && phoneNumber.trim() !== ""
            ? phoneNumber.trim()
            : null;
        let username = `${firstName}.${lastName}`.toLowerCase();

        // Ensure username is unique
        let existingUsername = await User.findOne({ where: { username } });
        let counter = 1;
        while (existingUsername) {
            username = `${firstName}.${lastName}${counter}`.toLowerCase();
            existingUsername = await User.findOne({ where: { username } });
            counter++;
        }

        const whereClause = {};
        if (cleanedEmail) whereClause.email = cleanedEmail;
        if (cleanedPhone) whereClause.phoneNumber = cleanedPhone;

        if (Object.keys(whereClause).length > 0) {
            const existingUser = await User.findOne({ where: whereClause });
            if (existingUser) {
                return res.status(400).json({ error: "Email or Phone Number already exists" });
            }
        }

        if (!password || password.trim() === "") {
            return res.status(400).json({ error: "Password is required" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const profileImage = req.file ? req.file.filename : DEFAULT_PROFILE_IMAGE;

        console.log("Creating new user with data:", {
            firstName,
            lastName,
            username,
            email: cleanedEmail,
            phoneNumber: cleanedPhone,
            dateOfBirth,
            password: hashedPassword,
            profileImage
        });

        const newUser = await User.create({
            firstName,
            lastName,
            username,
            email: cleanedEmail,
            phoneNumber: cleanedPhone,
            dateOfBirth,
            password: hashedPassword,
            profileImage
        });

        // Send only ONE response
        return res.status(201).json({ success: true, message: "User registered successfully", userId: newUser.id });

    } catch (error) {
        console.error("Registration Error:", error);

        if (!res.headersSent) {
            return res.status(500).json({ error: "Internal Server Error" });
        }
    }
});




server.listen(5000, () => console.log('Server running on port 5000'));
