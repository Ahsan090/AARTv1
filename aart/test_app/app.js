const express = require('express');
const app = express();

// VULNERABLE: no ownership check
app.get('/invoices/:id', authMiddleware, async (req, res) => {
    const invoice = await Invoice.findById(req.params.id);
    res.json(invoice);
});

// SAFE: ownership check present
app.get('/users/:id', authMiddleware, async (req, res) => {
    const user = await User.findById(req.params.id);
    if (user._id.toString() !== req.user.id) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    res.json(user);
});

// VULNERABLE: mass assignment
app.post('/users/:id', authMiddleware, async (req, res) => {
    const user = await User.findByIdAndUpdate(req.params.id, req.body);
    res.json(user);
});

app.post('/users', authMiddleware, isAdmin, async (req, res) => {
    const user = await User.create(req.body);
    res.json(user);
});

app.delete('/invoices/:id', authMiddleware, isAdmin, async (req, res) => {
    await Invoice.findByIdAndDelete(req.params.id);
    res.json({ deleted: true });
});