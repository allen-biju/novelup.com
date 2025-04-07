const { Sequelize, DataTypes, Op } = require('sequelize');

const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
    host: process.env.DB_HOST,
    dialect: 'mysql',
});

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
    is_admin: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
}, { timestamps: false });

const Book = sequelize.define('Book', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    title: { type: DataTypes.STRING, allowNull: false },
    author: { type: DataTypes.STRING, allowNull: false },
    rentPrice: { type: DataTypes.FLOAT, allowNull: false },
    actualPrice: { type: DataTypes.FLOAT, allowNull: false },
    language: { type: DataTypes.STRING, allowNull: false },
    category: { type: DataTypes.STRING, allowNull: false },
    description: { type: DataTypes.TEXT, allowNull: true },
    coverImage: { type: DataTypes.STRING, allowNull: false },
    availability: {
        type: Sequelize.ENUM('available', 'not_available'),
        allowNull: false,
        defaultValue: 'available'
    },
    userId: { type: DataTypes.INTEGER, allowNull: true },
    copies: {
        type: DataTypes.INTEGER,
        allowNull: false,
        defaultValue: 1
    }

}, { timestamps: true });

const Rental = sequelize.define('Rental', {
    pickupDate: { type: DataTypes.DATE, allowNull: false },
    pickupLocation: { type: DataTypes.STRING, allowNull: false },
    paymentMethod: { type: DataTypes.STRING, allowNull: false },
    status: { type: DataTypes.STRING, defaultValue: 'Pending' },
    userId: { type: DataTypes.INTEGER, allowNull: false },
    bookId: { type: DataTypes.INTEGER, allowNull: false },
    returnDate: { type: DataTypes.DATE, allowNull: true, defaultValue: null }
});

User.hasMany(Rental, { foreignKey: "userId" });
Book.hasMany(Rental, { foreignKey: "bookId" });
Rental.belongsTo(User, { foreignKey: "userId" });
Rental.belongsTo(Book, { foreignKey: "bookId" });

module.exports = { sequelize, Sequelize, DataTypes, Op, User, Book, Rental };
