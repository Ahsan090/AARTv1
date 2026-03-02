const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const JWT_SECRET = 'aart_sandbox_secret';

// ─────────────────────────────────────────
// In-memory database (seeded on startup)
// ─────────────────────────────────────────
const db = {
    users: [
        { _id: '1', email: 'user_a@test.com', password: 'password123', isAdmin: false },
        { _id: '2', email: 'user_b@test.com', password: 'password123', isAdmin: false },
        { _id: '3', email: 'admin@test.com',  password: 'password123', isAdmin: true  },
    ],
    invoices: [
        { _id: '101', userId: '1', amount: 500,  description: 'Invoice for user_a' },
        { _id: '102', userId: '2', amount: 1000, description: 'Invoice for user_b' },
        { _id: '103', userId: '3', amount: 250,  description: 'Invoice for admin'  },
    ]
};

// ─────────────────────────────────────────
// Middleware
// ─────────────────────────────────────────
function authMiddleware(req, res, next) {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        const token = header.split(' ')[1];
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (e) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

function isAdmin(req, res, next) {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    next();
}

// ─────────────────────────────────────────
// Auth routes
// ─────────────────────────────────────────

// Login — returns a JWT
app.post('/auth/login', (req, res) => {
    const { email, password } = req.body;
    const user = db.users.find(u => u.email === email);
    if (!user || user.password !== password) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign(
        { id: user._id, email: user.email, isAdmin: user.isAdmin },
        JWT_SECRET,
        { expiresIn: '1h' }
    );
    res.json({ token, userId: user._id });
});

// ─────────────────────────────────────────
// User routes
// ─────────────────────────────────────────

// List all users (auth only — privilege inconsistency vs POST /users)
app.get('/users', authMiddleware, (req, res) => {
    res.json(db.users.map(u => ({ _id: u._id, email: u.email })));
});

// SAFE: ownership check present
app.get('/users/:id', authMiddleware, (req, res) => {
    const user = db.users.find(u => u._id === req.params.id);
    if (!user) return res.status(404).json({ error: 'Not found' });
    if (user._id !== req.user.id) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    res.json({ _id: user._id, email: user.email });
});

// VULNERABLE: mass assignment — req.body goes straight into update
app.post('/users/:id', authMiddleware, (req, res) => {
    const user = db.users.find(u => u._id === req.params.id);
    if (!user) return res.status(404).json({ error: 'Not found' });
    Object.assign(user, req.body);  // ← mass assignment
    res.json(user);
});

// Admin only — create user
app.post('/users', authMiddleware, isAdmin, (req, res) => {
    const newUser = { _id: String(db.users.length + 1), ...req.body };
    db.users.push(newUser);
    res.json(newUser);
});

// ─────────────────────────────────────────
// Invoice routes
// ─────────────────────────────────────────

// VULNERABLE: no ownership check — classic IDOR
app.get('/invoices/:id', authMiddleware, (req, res) => {
    const invoice = db.invoices.find(i => i._id === req.params.id);
    if (!invoice) return res.status(404).json({ error: 'Not found' });
    res.json(invoice);  // ← returns regardless of who owns it
});

// Admin only
app.delete('/invoices/:id', authMiddleware, isAdmin, (req, res) => {
    const idx = db.invoices.findIndex(i => i._id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });
    db.invoices.splice(idx, 1);
    res.json({ deleted: true });
});

// ─────────────────────────────────────────
// Start server
// ─────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`AART test server running on port ${PORT}`);
});

module.exports = app;
