const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { PrismaClient } = require('@prisma/client');
const { execSync } = require('child_process');

const prisma = new PrismaClient();
const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'devseas_super_secret_key_2026';

// --- Email Transporter Configuration ---
// Configure these in your Render/Local environment variables
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: process.env.SMTP_PORT || 587,
    secure: false, // true for 465, false for other ports
    auth: {
        user: process.env.SMTP_USER, // Your email
        pass: process.env.SMTP_PASS  // Your app-specific password
    }
});

// --- PRODUCTION NOTE ---
// Do not use automatic 'prisma db push' or 'seed.js' on every restart in production.
// This can cause data loss if there are schema mismatches or if seed.js resets records.
// Run migrations during build time or manually.

// Test Database Connection
prisma.$connect()
    .then(() => console.log('✅ Successfully connected to Database'))
    .catch(err => console.error('❌ Database connection error:', err));

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure Multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, 'public', 'uploads'));
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// API Routes
app.get('/api/products', async (req, res) => {
    try {
        const products = await prisma.product.findMany({
            where: { isActive: true },
            include: { category: true }
        });
        res.json(products);
    } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).json({ error: 'Internal server error', details: error.message });
    }
});

app.get('/api/categories', async (req, res) => {
    try {
        const categories = await prisma.category.findMany({
            include: { products: true }
        });
        res.json(categories);
    } catch (error) {
        console.error('Error fetching categories:', error);
        res.status(500).json({ error: 'Internal server error', details: error.message });
    }
});

app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, phone, subject, message } = req.body;

        // Simple validation
        if (!name || !email || !message) {
            return res.status(400).json({ error: 'Name, email, and message are required' });
        }

        const inquiry = await prisma.inquiry.create({
            data: {
                name,
                email,
                phone,
                subject,
                message
            }
        });

        res.status(201).json({ success: true, message: 'Message sent successfully!', data: inquiry });
    } catch (error) {
        console.error('Error submitting inquiry:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        if (!user.isAdmin) {
            return res.status(403).json({ error: 'Access denied. Admins only.' });
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1d' });

        res.json({ success: true, token, user: { id: user.id, email: user.email, name: user.name } });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            error: 'Internal server error', 
            message: error.message,
            code: error.code || 'UNKNOWN_ERROR'
        });
    }
});

// --- FORGOT PASSWORD ENDPOINTS ---
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        console.log(`🔍 DEBUG: Request received for password reset: ${email}`);
        if (!email) return res.status(400).json({ error: 'Email is required' });

        const user = await prisma.user.findUnique({ where: { email } });
        console.log(`🔍 DEBUG: User found in DB: ${user ? 'Yes (' + user.name + ')' : 'No'}`);
        
        if (!user) {
            // Act as if it was sent for security
            return res.json({ success: true, message: 'If an account exists, a reset link has been sent.' });
        }

        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour

        await prisma.user.update({
            where: { id: user.id },
            data: { resetToken, resetTokenExpiry }
        });

        const resetLink = `${req.protocol}://${req.get('host')}/admin-reset-password.html?token=${resetToken}`;
        
        // --- Try sending email ---
        if (process.env.SMTP_USER && process.env.SMTP_PASS) {
            const mailOptions = {
                from: `"Devseas Global Admin" <${process.env.SMTP_USER}>`,
                to: user.email,
                subject: 'Admin Password Reset Request',
                html: `
                    <div style="font-family: sans-serif; padding: 20px; color: #333;">
                        <h2>Password Reset Requested</h2>
                        <p>Hi ${user.name}, you requested a password reset for the admin panel.</p>
                        <p>Click the button below to reset your password. This link is valid for 1 hour.</p>
                        <a href="${resetLink}" style="display:inline-block; padding:12px 24px; background:#2dd4bf; color:#0f172a; text-decoration:none; border-radius:8px; font-weight:bold;">Reset Password</a>
                        <p style="margin-top:20px; font-size:12px; color:#666;">If you didn't request this, please ignore this email.</p>
                    </div>
                `
            };

            await transporter.sendMail(mailOptions);
            console.log(`✅ Reset email sent to: ${user.email}`);
        } else {
            console.log('⚠️  SMTP credentials not set. Logging reset link instead:');
            console.log('🔗 RESET LINK:', resetLink);
        }

        res.json({ success: true, message: 'Password reset instructions have been sent.' });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ error: 'Failed to process request' });
    }
});

app.post('/api/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        if (!token || !newPassword) return res.status(400).json({ error: 'Token and new password are required' });

        const user = await prisma.user.findFirst({
            where: {
                resetToken: token,
                resetTokenExpiry: { gt: new Date() }
            }
        });

        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired reset token' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await prisma.user.update({
            where: { id: user.id },
            data: {
                password: hashedPassword,
                resetToken: null,
                resetTokenExpiry: null
            }
        });

        res.json({ success: true, message: 'Password has been reset successfully.' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

// Auth Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.status(401).json({ error: 'Unauthorized' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Forbidden' });
        req.user = user;
        next();
    });
};

app.get('/api/inquiries', authenticateToken, async (req, res) => {
    try {
        const inquiries = await prisma.inquiry.findMany({
            orderBy: { createdAt: 'desc' }
        });
        res.json(inquiries);
    } catch (error) {
        console.error('Error fetching inquiries:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/inquiries', authenticateToken, async (req, res) => {
    try {
        await prisma.inquiry.deleteMany({});
        res.json({ success: true, message: 'All inquiries cleared successfully.' });
    } catch (error) {
        console.error('Error clearing inquiries:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/categories', authenticateToken, async (req, res) => {
    try {
        const { name, description } = req.body;
        if (!name) return res.status(400).json({ error: 'Name is required' });

        const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)+/g, '');

        const category = await prisma.category.create({
            data: { name, slug, description }
        });
        res.status(201).json(category);
    } catch (error) {
        console.error('Error creating category:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/categories/:id', authenticateToken, async (req, res) => {
    try {
        const { name, description } = req.body;
        const data = {};
        if (name) {
            data.name = name;
            data.slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)+/g, '');
        }
        if (description !== undefined) data.description = description;

        const category = await prisma.category.update({
            where: { id: parseInt(req.params.id) },
            data
        });
        res.json(category);
    } catch (error) {
        console.error('Error updating category:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/categories/:id', authenticateToken, async (req, res) => {
    try {
        await prisma.category.delete({ where: { id: parseInt(req.params.id) } });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/products', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        let { name, categoryId, description, price, isActive, cas_number, chemical_formula, purity, grade } = req.body;
        if (!name || !categoryId) return res.status(400).json({ error: 'Name and Category are required' });

        const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)+/g, '') + '-' + Date.now().toString().slice(-4);

        const data = {
            name,
            slug,
            description,
            isActive: isActive !== "false" && isActive !== false,
            categoryId: parseInt(categoryId),
            casNumber: cas_number || null,
            formula: chemical_formula || null,
            purity: purity || '99%',
            grade: grade || 'IP/BP/USP',
            price: price || null
        };

        if (req.file) {
            data.image = req.file.filename;
        }

        const product = await prisma.product.create({ data });
        res.status(201).json(product);
    } catch (error) {
        console.error('Error creating product:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/products/:id', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        let { name, categoryId, description, price, isActive, cas_number, chemical_formula, purity, grade } = req.body;

        const data = {};
        if (name) {
            data.name = name;
            data.slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)+/g, '') + '-' + Date.now().toString().slice(-4);
        }
        if (description !== undefined) data.description = description;
        if (isActive !== undefined) data.isActive = isActive !== "false" && isActive !== false;
        if (categoryId) data.categoryId = parseInt(categoryId);
        if (cas_number !== undefined) data.casNumber = cas_number || null;
        if (chemical_formula !== undefined) data.formula = chemical_formula || null;
        if (purity !== undefined) data.purity = purity || '99%';
        if (grade !== undefined) data.grade = grade || 'IP/BP/USP';
        if (price !== undefined) data.price = price || null;

        if (req.file) {
            data.image = req.file.filename;
        }

        const product = await prisma.product.update({
            where: { id: parseInt(req.params.id) },
            data
        });
        res.json(product);
    } catch (error) {
        console.error('Error updating product:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    try {
        await prisma.product.delete({ where: { id: parseInt(req.params.id) } });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- Catalogue API ---
app.get('/api/catalogues', async (req, res) => {
    try {
        const catalogues = await prisma.catalogue.findMany({
            where: { isActive: true },
            orderBy: { createdAt: 'desc' }
        });
        res.json(catalogues);
    } catch (error) {
        console.error('Error fetching catalogues:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/catalogues', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        const { name } = req.body;
        if (!name || !req.file) return res.status(400).json({ error: 'Name and File are required' });

        const catalogue = await prisma.catalogue.create({
            data: {
                name,
                fileName: req.file.originalname,
                fileUrl: req.file.filename
            }
        });
        res.status(201).json(catalogue);
    } catch (error) {
        console.error('Error creating catalogue:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/catalogues/:id', authenticateToken, async (req, res) => {
    try {
        await prisma.catalogue.delete({ where: { id: parseInt(req.params.id) } });
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting catalogue:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin Routes
app.get('/admin/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-login.html'));
});

app.get('/admin/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

app.get('/admin/products', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-products.html'));
});

app.get('/admin/categories', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-categories.html'));
});

app.get('/admin/catalogues', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-catalogues.html'));
});

// Fallback to index.html for single-page app or static HTML navigation
app.get(/.*/, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
