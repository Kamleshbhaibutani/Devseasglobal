const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const { PrismaClient } = require('@prisma/client');

const { execSync } = require('child_process');
const prisma = new PrismaClient();
const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'devseas_super_secret_key_2026';

// Production Database Sync (for Render)
if (process.env.NODE_ENV === 'production') {
    try {
        const dbUrl = process.env.DATABASE_URL || '';
        console.log('🚀 Production environment detected. Syncing database...');
        
        if (dbUrl) {
            // Ensure client is generated and schema is pushed
            const { execSync } = require('child_process');
            console.log('🔄 Running: npx prisma db push...');
            execSync('npx prisma db push --accept-data-loss', { stdio: 'inherit' });
            
            console.log('🌱 Running: node prisma/seed.js...');
            execSync('node prisma/seed.js', { stdio: 'inherit' });
            
            console.log('✅ Database production sync complete');
        }
    } catch (err) {
        console.error('❌ Production database sync failed:', err.message);
    }
}

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
