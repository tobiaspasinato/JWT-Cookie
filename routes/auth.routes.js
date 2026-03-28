const express = require('express');
const router = express.Router();
const dotenv = require('dotenv');
dotenv.config();

const cookieParser = require('cookie-parser');
router.use(cookieParser());

const db = require('../db/database.js');
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");


// Register route
router.post('/register', async (req, res) => {
    const { email, password } = req.body;

    // Check if user already exists
    const [existingUser] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
    if (existingUser.length > 0) {
        return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user into the database
    await db.query('INSERT INTO usuarios (email, password_hash) VALUES (?, ?)', [email, hashedPassword]);
    res.status(201).json({ message: 'User registered successfully' });
});

// Login route
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    // Check if user exists
    const [user] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
    if (user.length === 0) {
        return res.status(400).json({ message: 'Invalid email or password' });
    }
    const validPassword = await bcrypt.compare(password, user[0].password_hash);
    if (!validPassword) {
        return res.status(400).json({ message: 'Invalid email or password' });
    }
    // Generate a JWT token
    const token = jwt.sign({ sub: user[0].id, email: user[0].email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    // Enviar como cookie httpOnly
    res.cookie('token', token, {
        httpOnly: true,      // No accesible desde JavaScript
        secure: process.env.NODE_ENV === 'production',  // Solo HTTPS en producción
        sameSite: 'strict',  // Protección contra CSRF
        maxAge: 3600000      // 1 hora en millisegundos
    });
    res.json({ message: 'Login successful' });
});

// verifica que el token es válido para acceder a rutas protegidas
router.get("/me", (req, res) => {
    // toma el token de las cookies
    const token = req.cookies.token;

    // Si no hay token, el usuario no está autenticado
    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    // Verifica el token y devuelve la información del usuario si es válido
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        res.json({ message: 'Acceso permitido', user: decoded });
    } catch (err) {
        return res.status(401).json({ message: 'Token inválido' });
    }
});


module.exports = router;