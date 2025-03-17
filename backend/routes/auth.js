const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../config/db');  // Ensure correct path
const jwt = require('jsonwebtoken');
require('dotenv').config();

const router = express.Router();

// User Registration
router.post('/register', async (req, res) => {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    // Check if user already exists
    db.query('SELECT email FROM users WHERE email = ?', [email], async (err, results) => {
        if (results.length > 0) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new user
        db.query('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
            [name, email, hashedPassword, role],
            (err, result) => {
                if (err) return res.status(500).json({ message: 'Database error' });

                res.status(201).json({ message: 'User registered successfully' });
            }
        );
    });
});

// User Login
router.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (results.length === 0) {
            return res.status(400).json({ message: 'User not found' });
        }

        const user = results[0];
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ token, role: user.role, name: user.name });
    });
});

module.exports = router;
