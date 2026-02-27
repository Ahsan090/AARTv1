// test_app/app.js
const express = require('express');
const app = express();

app.get('/users', authMiddleware, getUsers);
app.get('/users/:id', authMiddleware, getUser);
app.post('/users', authMiddleware, isAdmin, createUser);
app.get('/invoices/:id', authMiddleware, getInvoice);   // <-- classic IDOR candidate
app.delete('/invoices/:id', authMiddleware, isAdmin, deleteInvoice);