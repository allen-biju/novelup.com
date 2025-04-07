const express = require('express');
const cors = require('cors');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const stripe = require('stripe')('your-stripe-secret-key');
const http = require('http');
const socketIo = require('socket.io');
const authRoutes = require('./routes/authRoutes');
const { User, Book, Rental, sequelize, Op } = require('./models');
require('dotenv').config();
// Make sure to sync the model with the database (for initial testing)
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const corsOptions = {
    origin: ['http://127.0.0.1:5500', 'http://localhost:5500'],  // Allow frontend requests (adjust if needed)
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allow necessary methods
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
};
app.use(cors(corsOptions)); // Enable CORS with the custom options
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads/profile_pictures', express.static(path.join(__dirname, 'uploads/profile_pictures')));
app.use('/uploads/book_images', express.static(path.join(__dirname, 'uploads/book_images')));
app.use('/', authRoutes); // mounts forgot-password at /forgot-password

// Ensure directories exist
const ensureDirExists = (dir) => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
};
ensureDirExists('uploads/profile_pictures');
ensureDirExists('uploads/book_images');

const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,       // Your Gmail address
        pass: process.env.EMAIL_PASS        // Your Gmail App Password
    }
});

// Multer Storage for Profile Pictures
const profileStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/profile_pictures/');
    },
    filename: (req, file, cb) => {
        cb(null, `profile-${Date.now()}${path.extname(file.originalname)}`);
    }
});
const router = express.Router();
// POST route to store rental details in the database
router.post('/rental', async (req, res) => {
    const { pickupDate, pickupLocation, paymentMethod } = req.body;

    // Ensure the user is logged in (authentication)
    if (!req.user) {
        return res.status(401).json({ message: 'Unauthorized. Please log in.' });
    }

    try {
        // Create a new rental record in the database
        const rental = await Rental.create({
            userId: req.user.id, // assuming you have user info in `req.user`
            pickupDate,
            pickupLocation,
            paymentMethod,
            status: 'Pending' // You can add status or any other additional fields
        });

        // Return success response
        res.status(201).json({ success: true, rental });
    } catch (error) {
        console.error('Error storing rental details:', error);
        res.status(500).json({ message: 'Failed to store rental details. Please try again.' });
    }
});

module.exports = router;
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
const bookUpload = multer({
    storage: bookStorage,
    // fileFilter: (req, file, cb) => {
    //     if (!file.mimetype.startsWith('image/')) {
    //         return cb(new Error('Only image files are allowed'), false);
    //     }
    //     cb(null, true);
    // }
});

// Connect and sync with the database
sequelize.authenticate()
    .then(() => {
        console.log('MySQL Connected');
        return sequelize.sync();
    })
    .then(() => {
        console.log("Database synchronized");
    })
    .catch(err => {
        console.error('Error: ' + err);
    });


const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify token with secret key
        req.user = decoded; // Attach user info to the request
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid or expired token' });
    }
};

module.exports = authenticateToken;
// User Model


const authenticateAdmin = async (req, res, next) => {
    const authHeader = req.header('Authorization');

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Access denied. Invalid token format." });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findByPk(decoded.id);

        if (!user || !user.is_admin) {
            return res.status(403).json({ error: "Unauthorized. Admin access required." });
        }

        req.user = user; // Attach user to request
        next();
    } catch (error) {
        res.status(400).json({ error: "Invalid token" });
    }
};





// Middleware to Authenticate Users
const authenticateUser = (req, res, next) => {
    const authHeader = req.header('Authorization');

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Access denied. Invalid token format." });
    }

    const token = authHeader.split(" ")[1];

    if (!token) {
        console.error('Token is missing in the authorization header');
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        // Verify token using JWT secret
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log('Decoded Token:', decoded);
        req.user = decoded; // Add user info (decoded token) to the request object
        next(); // Move to the next middleware/route handler
    } catch (error) {
        console.error("Token verification error:", error); // Log error for debugging
        res.status(400).json({ error: 'Invalid or expired token.' });
    }
};



app.post('/send-otp', async (req, res) => {
    const { firstName, lastName, email, phoneNumber, dateOfBirth, password } = req.body;

    if (!firstName || !lastName || !password || !dateOfBirth) {
        return res.status(400).json({ error: 'First name, last name, password, and date of birth are required' });
    }

    if (!email && !phoneNumber) {
        return res.status(400).json({ error: 'Either an email or phone number is required.' });
    }

    const contact = email || phoneNumber;
    const otp = generateOTP();

    otpStore[contact] = {
        otp,
        userData: { firstName, lastName, email, phoneNumber, dateOfBirth, password },
        expiresAt: Date.now() + 5 * 60 * 1000 // 5 minutes
    };

    if (email) {
        await transporter.sendMail({
            from: `"Book Rental Service" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: "Your OTP for Book Rental Registration",
            html: `
          <h2>OTP Verification</h2>
          <p>Hello ${firstName},</p>
          <p>Your OTP is: <strong>${otp}</strong></p>
          <p>It is valid for 5 minutes.</p>
        `
        });
    } else {
        console.log(`Mock SMS to ${phoneNumber}: Your OTP is ${otp}`);
        // Integrate Twilio or SMS API if needed
    }

    res.json({ success: true, message: `OTP sent to ${email || phoneNumber}` });
});
app.post('/login', async (req, res) => {
    try {
        const { usernameoremail, password } = req.body;

        if (!usernameoremail || !password) {
            return res.status(400).json({ error: 'Username or email, and password are required' });
        }

        // Find user by username or email
        const user = await User.findOne({
            where: {
                [Op.or]: [
                    { username: usernameoremail },
                    { email: usernameoremail }
                ]
            }
        });

        if (!user) {
            return res.status(401).json({ error: 'User not found or incorrect username/email' });
        }

        // Compare the provided password with the stored hash
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Incorrect password' });
        }

        // Generate JWT token
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ success: true, token, user: { id: user.id, username: user.username, email: user.email, isAdmin: user.is_admin } });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Internal Server Error', details: error.message });
    }
});

// Upload Profile Picture (Standalone API)
app.post('/upload-profile-picture', authenticateUser, profileUpload.single('profileImage'), async (req, res) => {
    try {
        console.log("Incoming File:", req.file); // Debugging uploaded file
        console.log("Headers:", req.headers); // Debugging headers
        console.log("User Data:", req.user); // Debugging user data

        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        const profileImagePath = req.file.filename;
        await User.update({ profileImage: profileImagePath }, { where: { id: req.user.id } });
        res.json({ success: true, message: 'Profile picture uploaded successfully', profileImage: profileImagePath });
    } catch (error) {
        console.error("Error uploading profile picture picture:", error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
app.get('/user/profile-picture', authenticateUser, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id);
        if (!user || !user.profileImage) {
            return res.status(404).json({ success: false, message: 'Profile image not found' });
        }

        res.json({
            success: true,
            profileImageUrl: `http://localhost:5000/uploads/profile_pictures/${user.profileImage}`
        });
    } catch (error) {
        console.error("Error fetching profile image:", error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/set-default-profile', authenticateUser, async (req, res) => {
    try {


        await User.update({ profileImage: "default.jpg" }, { where: { id: req.user.id } });

        res.json({ success: true, message: "Default profile picture set." });
    } catch (error) {
        console.error("Error setting default profile picture:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});
// Admin Login Route
app.post('/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if the admin exists and the password matches
        const admin = await User.findOne({ where: { email, is_admin: true } });

        if (!admin) {
            return res.status(401).json({ error: 'Admin not found or incorrect email' });
        }

        // Compare password with the hashed password
        const isMatch = await bcrypt.compare(password, admin.password);

        if (!isMatch) {
            return res.status(401).json({ error: 'Incorrect password' });
        }

        // Generate a JWT token
        const token = jwt.sign({ id: admin.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Send the token back in the response
        res.json({ success: true, token });
    } catch (error) {
        console.error('Error during admin login:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.post('/admin/upload-book', authenticateAdmin, bookUpload.single('bookImage'), async (req, res) => {
    try {
        console.log("Incoming Book Data:", req.body);  // Log incoming fields
        console.log("Uploaded File:", req.file);       // Log the file upload
        const { title, author, rentPrice, actualPrice, language, category, description, availability } = req.body;
        if (!title || !author || !rentPrice || !actualPrice || !language || !category || !availability || !req.file) {
            return res.status(400).json({ error: "All fields (title, author, price,lang,category,avail, image) are required" });
        }
        const existingBook = await Book.findOne({ where: { title, author, language } });
        if (existingBook) {
            return res.status(400).json({ error: "Book with this title,  author and language already exists." });
        }
        const coverImage = req.file.filename;

        const newBook = await Book.create({
            title,
            author,
            rentPrice,
            actualPrice,
            language,
            category,
            description,
            coverImage,
            availability,
            userId: req.user.id
        });

        res.json({ success: true, message: "Book uploaded successfully", book: newBook });
    } catch (error) {
        console.error("Error uploading book:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});
app.get('/books', async (req, res) => {
    try {
        const books = await Book.findAll();
        const formattedBooks = books.map(book => ({
            id: book.id,
            title: book.title,
            author: book.author,
            language: book.language,
            category: book.category,
            rentPrice: book.rentPrice,
            actualPrice: book.actualPrice,
            coverImage: book.coverImage,
            rating: book.rating || 'N/A',
            available: book.availability === 'available' // Converts string to boolean
        }));

        res.json({ success: true, books: formattedBooks });
    } catch (error) {
        console.error("Error fetching books:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});
// Get book details for regular users
app.get('/books/:id', async (req, res) => {
    try {
        const book = await Book.findByPk(req.params.id);
        if (!book) {
            return res.status(404).json({ error: 'Book not found' });
        }

        res.json({
            id: book.id,
            title: book.title,
            author: book.author,
            rentPrice: book.rentPrice,
            actualPrice: book.actualPrice,
            language: book.language,
            category: book.category,
            description: book.description,
            coverImage: book.coverImage,
            availability: book.availability,
        });
    } catch (error) {
        console.error('Error fetching book details:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Get book details for editing
app.get('/admin/book/:id', authenticateAdmin, async (req, res) => {
    try {
        const book = await Book.findByPk(req.params.id); // Find the book by ID
        if (!book) {
            return res.status(404).json({ error: "Book not found" });
        }
        res.json(book); // Send book details
    } catch (error) {
        console.error("Error fetching book details:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});
// Update book details
app.put('/admin/update-book/:id', authenticateAdmin, bookUpload.single('bookImage'), async (req, res) => {
    try {
        const { title, author, rentPrice, actualPrice, language, category, description, availability } = req.body;
        const coverImage = req.file ? req.file.filename : null; // Handle optional cover image

        // Find the book by ID
        const book = await Book.findByPk(req.params.id);

        if (!book) {
            return res.status(404).json({ error: "Book not found" });
        }

        // Update book details
        book.title = title || book.title;
        book.author = author || book.author;
        book.rentPrice = rentPrice || book.rentPrice;
        book.actualPrice = actualPrice || book.actualPrice;
        book.language = language || book.language;
        book.category = category || book.category;
        book.description = description || book.description;
        book.availability = availability || book.availability;

        // If there's a new cover image, update it
        if (coverImage) {
            book.coverImage = coverImage;
        }

        await book.save(); // Save updated book in the database

        res.json({ success: true, message: "Book updated successfully", book });
    } catch (error) {
        console.error("Error updating book:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.get('/user/details', authenticateUser, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id, {
            attributes: ['firstName', 'lastName', 'username']
        });

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        res.json({ success: true, name: `${user.firstName} ${user.lastName}`, username: user.username });
    } catch (error) {
        console.error("Error fetching user details:", error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});


app.delete('/admin/remove-book/:id', authenticateAdmin, async (req, res) => {
    try {
        const book = await Book.findByPk(req.params.id);
        if (!book) {
            return res.status(404).json({ error: "Book not found" });
        }
        await book.destroy();
        res.json({ success: true, message: 'Book removed successfully' });
    } catch (error) {
        console.error("Error removing book:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});
// Rent endpoint
app.post('/rental', authenticateUser, async (req, res) => {

    console.log("Incoming Request Body:", req.body);
    console.log("Parsed Data ->", {
        pickupDate: req.body.pickupDate,
        pickupLocation: req.body.pickupLocation,
        paymentMethod: req.body.paymentMethod
    });
    const { bookId, pickupDate, pickupLocation, paymentMethod } = req.body;
    const userId = req.user.id;
    console.log("📌 Debug - Received rental request:", { bookId, pickupDate, pickupLocation, paymentMethod, userId });

    if (!bookId || !pickupDate || !pickupLocation || !paymentMethod) {
        console.log('Missing fields:', { bookId, pickupDate, pickupLocation, paymentMethod }); // ✅ Log missing fields
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        // 🔍 Ensure book exists before inserting rental record
        const book = await Book.findByPk(bookId);
        if (!book) {
            console.log(`❌ Book with ID ${bookId} not found`);
            return res.status(404).json({ message: 'Book not found' });
        }

        console.log('User ID:', userId, 'Book ID:', bookId);
        // Log the received userId and bookId
        const rental = await Rental.create({
            userId,
            bookId,
            pickupDate: new Date(pickupDate), // Ensure it's a Date object
            pickupLocation,
            paymentMethod,
            status: "Pending",
        });

        console.log(`Book rented successfully: User ${userId} rented book ${bookId}`);
        res.json({ message: 'Book rented successfully!' });

    }
    catch (error) {
        console.error('Error renting book:', error);  // Log error for debugging
        res.status(500).json({ message: 'Server error. Try again later.' });
    }

});
app.get('/rentals', authenticateUser, async (req, res) => {
    try {
        const rentals = await Rental.findAll({
            where: { userId: req.user.id },
            include: [{ model: Book, attributes: ['title', 'author', 'coverImage', 'rentPrice', 'actualPrice', 'language', 'category'] }]
        });
        const rentalsWithImages = rentals.map(rental => ({
            ...rental.toJSON(),
            Book: rental.Book ? {  // Ensure Book exists before accessing properties
                title: rental.Book.title,
                author: rental.Book.author,
                rentPrice: rental.Book.rentPrice,
                actualPrice: rental.Book.actualPrice,
                language: rental.Book.language,
                category: rental.Book.category,
                coverImage: rental.Book.coverImage
                    ? `http://localhost:5000/uploads/book_images/${rental.Book.coverImage}`
                    : 'http://localhost:5000/images/placeholder.jpg'
            } : null
        }));

        res.json(rentalsWithImages);
    } catch (error) {
        console.error('Error fetching rentals:', error);
        res.status(500).json({ message: 'Server error' });
    }
});
app.delete('/rental/:id', authenticateUser, async (req, res) => {
    try {
        const rental = await Rental.findOne({ where: { id: req.params.id, userId: req.user.id } });
        if (!rental) return res.status(404).json({ message: 'Rental not found' });

        await rental.destroy();
        res.json({ message: 'Rental order canceled successfully' });
    } catch (error) {
        console.error('Error canceling rental:', error);
        res.status(500).json({ message: 'Server error' });
    }
});
app.get('/orders', authenticateAdmin, async (req, res) => {
    try {
        const orders = await Rental.findAll({
            include: [
                {
                    model: Book,
                    attributes: ['title', 'author', 'coverImage']
                },
                {
                    model: User,
                    attributes: ['username', 'email']
                }
            ],
            order: [['createdAt', 'DESC']]
        });

        const formattedOrders = orders.map(order => ({
            id: order.id,
            bookTitle: order.Book.title,
            author: order.Book.author,
            coverImage: order.Book.coverImage,
            username: order.User.username,
            email: order.User.email,
            phoneNumber: order.User.phoneNumber,
            pickupDate: order.pickupDate,
            pickupLocation: order.pickupLocation,
            paymentMethod: order.paymentMethod,
            status: order.status,
            returnDate: order.returnDate
        }));

        res.json({ success: true, orders: formattedOrders });
    } catch (error) {
        console.error("Error fetching orders:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});
app.put('/orders/update-status/:orderId', authenticateAdmin, async (req, res) => {
    const { orderId } = req.params;
    const { status } = req.body;

    try {
        const result = await Rental.update({ status }, {
            where: { id: orderId }
        });

        console.log("Update result:", result);

        res.json({ success: true, message: "Order status updated" });
    } catch (err) {
        console.error("Error updating order status:", err);
        res.status(500).json({ success: false, message: "Failed to update status" });
    }
});
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    try {
        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.status(404).json({ error: "No user found with that email." });
        }

        // ✅ Generate JWT reset token (valid for 15 minutes)
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "15m" });

        // ✅ Create reset link
        const resetLink = `http://localhost:5500/reset-password.html?token=${token}`;

        // ✅ Configure email transporter
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.EMAIL,
                pass: process.env.APP_PASSWORD
            }
        });

        // ✅ Send the email
        await transporter.sendMail({
            from: `"Book Rental Support" <${process.env.EMAIL}>`,
            to: email,
            subject: "Password Reset Request",
            html: `
          <p>Hello,</p>
          <p>We received a request to reset your password. Click the link below to reset it:</p>
          <a href="${resetLink}">${resetLink}</a>
          <p>This link will expire in 15 minutes.</p>
          <p>If you did not request a password reset, you can ignore this email.</p>
        `
        });

        return res.json({ message: "Reset link sent to your email." });

    } catch (error) {
        console.error("Error in /forgot-password:", error);
        return res.status(500).json({ error: "Something went wrong." });
    }
});
app.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    try {
        // 1. Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // same secret used to create the token
        const userId = decoded.id;

        // 2. Find the user
        const user = await User.findByPk(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        // 3. Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // 4. Update the user's password
        await user.update({ password: hashedPassword });

        res.json({ message: 'Password has been reset successfully.' });
    } catch (err) {
        console.error('Reset password error:', err.message);
        if (err.name === 'TokenExpiredError') {
            return res.status(400).json({ error: 'Reset link has expired.' });
        }
        res.status(400).json({ error: 'Invalid or expired token.' });
    }
});

app.delete('/delete-account', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        await User.destroy({ where: { id: userId } });
        res.json({ success: true, message: 'Account deleted successfully' });
    } catch (error) {
        console.error("Delete account error:", error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});
const otpStore = new Map(); // In-memory store. Replace with DB for production
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Send OTP
app.post('/send-otp', async (req, res) => {
    const { firstName, lastName, email, phoneNumber, dateOfBirth, password } = req.body;

    const contact = email || phoneNumber;
    if (!contact) return res.status(400).json({ error: "Email or phone number is required" });

    const otp = generateOTP();
    const expiresAt = Date.now() + 5 * 60 * 1000;

    // Store full registration data with OTP
    otpStore[contact] = {
        otp,
        expiresAt,
        userData: { firstName, lastName, email, phoneNumber, dateOfBirth, password }
    };

    try {
        // Send OTP via email (assumes contact is email, but can later expand to SMS)
        await transporter.sendMail({
            from: `"Book Rental" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: "Your OTP for Registration",
            html: `
                <div style="font-family: Arial, sans-serif;">
                    <h2>OTP Verification</h2>
                    <p>Your OTP for registration is:</p>
                    <h1 style="letter-spacing: 2px;">${otp}</h1>
                    <p>This OTP is valid for <strong>5 minutes</strong>.</p>
                    <hr>
                    <p style="font-size: 12px; color: gray;">If you didn’t request this, please ignore.</p>
                </div>
            `
        });

        res.json({ message: "OTP sent to email" });
    } catch (error) {
        console.error("Error sending OTP email:", error);
        res.status(500).json({ error: "Failed to send OTP" });
    }
});


// Verify OTP and register user
app.post('/verify-otp', async (req, res) => {
    const { contact, otp } = req.body;
    const record = otpStore[contact];

    if (!record) return res.status(400).json({ error: "No OTP found or expired." });
    if (Date.now() > record.expiresAt) return res.status(400).json({ error: "OTP expired." });
    if (record.otp !== otp) return res.status(400).json({ error: "Invalid OTP." });

    const { firstName, lastName, email, phoneNumber, dateOfBirth, password } = record.userData;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({
            firstName,
            lastName,
            username: `${firstName}.${lastName}`.toLowerCase(),
            email: email || null,
            phoneNumber: phoneNumber || null,
            dateOfBirth,
            password: hashedPassword,
            profileImage: 'default.jpg'
        });

        const token = jwt.sign({ id: newUser.id }, process.env.JWT_SECRET, { expiresIn: "5h" });

        delete otpStore[contact]; // ✅ Clean up

        res.json({ success: true, message: "OTP verified and user registered", user: { id: newUser.id }, token });
    } catch (err) {
        console.error("Registration error after OTP:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post('/admin/update-status', async (req, res) => {
    const { rentalId, newStatus } = req.body;

    try {
        const rental = await Rental.findByPk(rentalId, { include: Book });
        if (!rental) return res.status(404).json({ error: "Rental not found" });

        rental.status = newStatus;
        await rental.save();

        const book = await Book.findByPk(rental.bookId);

        if (newStatus === 'Received') {
            if (book.copies > 0) {
                book.copies -= 1;
            } else {
                return res.status(400).json({ error: "No copies available" });
            }
        } else if (newStatus === 'Returned') {
            book.copies += 1;
        }

        await book.save();
        res.json({ message: "Status updated and book stock adjusted" });

    } catch (err) {
        console.error("Error updating status:", err);
        res.status(500).json({ error: "Server error" });
    }
});








server.listen(5000, () => console.log('Server running on port 5000'));
