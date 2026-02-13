const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();

// Security Middleware
app.use(helmet());

// CORS Configuration
const corsOptions = {
    origin: process.env.CORS_ORIGIN || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// Body Parser
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

// Health Check Route
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'house_construction_secret_key_2024';

// MongoDB Connection with options
const mongoOptions = {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
};

mongoose.connect(process.env.MONGODB_URI, mongoOptions)
    .then(() => {
        console.log('✓ MongoDB Connected Successfully');
        console.log(`✓ Database: ${mongoose.connection.name}`);
    })
    .catch(err => {
        console.error('✗ MongoDB Connection Error:', err.message);
        process.exit(1);
    });

// Mongoose Connection Events
mongoose.connection.on('error', (err) => {
    console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.warn('MongoDB disconnected. Attempting to reconnect...');
});

mongoose.connection.on('reconnected', () => {
    console.log('MongoDB reconnected');
});

// ==================== MODELS ====================

// User Model
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    phone: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'staff', 'customer'], default: 'customer' },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Material Category Model
const materialCategorySchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: String
});
const MaterialCategory = mongoose.model('MaterialCategory', materialCategorySchema);

// Material Model
const materialSchema = new mongoose.Schema({
    name: { type: String, required: true },
    category_id: { type: mongoose.Schema.Types.ObjectId, ref: 'MaterialCategory' },
    price_per_unit: { type: Number, required: true },
    unit: { type: String, default: 'unit' },
    createdAt: { type: Date, default: Date.now }
});
const Material = mongoose.model('Material', materialSchema);

// Worker Model
const workerSchema = new mongoose.Schema({
    name: { type: String, required: true },
    role: { type: String, default: 'Worker' },
    daily_wage: { type: Number, required: true },
    phone: String,
    createdAt: { type: Date, default: Date.now }
});
const Worker = mongoose.model('Worker', workerSchema);

// Project Model
const projectSchema = new mongoose.Schema({
    project_name: { type: String, required: true },
    customer_name: String,
    area_sqft: { type: Number, default: 0 },
    status: { type: String, enum: ['Planning', 'In Progress', 'Completed', 'Pending'], default: 'Planning' },
    start_date: Date,
    end_date: Date,
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now }
});
const Project = mongoose.model('Project', projectSchema);

// Project Material Model
const projectMaterialSchema = new mongoose.Schema({
    project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    material_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Material' },
    quantity: { type: Number, default: 0 },
    unit_price: { type: Number, default: 0 },
    total_cost: { type: Number, default: 0 }
});
const ProjectMaterial = mongoose.model('ProjectMaterial', projectMaterialSchema);

// Project Worker Model
const projectWorkerSchema = new mongoose.Schema({
    project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    worker_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Worker' },
    days: { type: Number, default: 0 },
    daily_wage: { type: Number, default: 0 },
    total_wage: { type: Number, default: 0 }
});
const ProjectWorker = mongoose.model('ProjectWorker', projectWorkerSchema);

// Quotation Model
const quotationSchema = new mongoose.Schema({
    project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    quotation_number: { type: String, required: true },
    material_cost: { type: Number, default: 0 },
    labor_cost: { type: Number, default: 0 },
    total_cost: { type: Number, default: 0 },
    gst_amount: { type: Number, default: 0 },
    grand_total: { type: Number, default: 0 },
    status: { type: String, enum: ['Pending', 'Approved', 'Rejected'], default: 'Pending' },
    createdAt: { type: Date, default: Date.now }
});
const Quotation = mongoose.model('Quotation', quotationSchema);

// Quotation Material Model
const quotationMaterialSchema = new mongoose.Schema({
    quotation_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Quotation' },
    material_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Material' },
    quantity: Number,
    unit_price: Number,
    total_cost: Number
});
const QuotationMaterial = mongoose.model('QuotationMaterial', quotationMaterialSchema);

// Quotation Worker Model
const quotationWorkerSchema = new mongoose.Schema({
    quotation_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Quotation' },
    worker_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Worker' },
    days: Number,
    daily_wage: Number,
    total_cost: Number
});
const QuotationWorker = mongoose.model('QuotationWorker', quotationWorkerSchema);

// ==================== MIDDLEWARE ====================

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// ==================== AUTH ROUTES ====================

// Login
app.post('/api/auth/login', async (req, res) => {
    const { phone, password } = req.body;
    try {
        const user = await User.findOne({ phone });
        if (!user) {
            return res.status(401).json({ success: false, message: 'User not found' });
        }
        if (user.password !== password) {
            return res.status(401).json({ success: false, message: 'Invalid password' });
        }
        const token = jwt.sign(
            { id: user._id, phone: user.phone, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                name: user.name,
                phone: user.phone,
                role: user.role
            }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Register
app.post('/api/auth/register', async (req, res) => {
    const { name, phone, password, role } = req.body;
    try {
        const newUser = new User({ name, phone, password, role: role || 'customer' });
        await newUser.save();
        res.json({ id: newUser._id, message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get current user profile
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update user profile
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
    const { name, phone } = req.body;
    try {
        const user = await User.findByIdAndUpdate(
            req.user.id,
            { name, phone },
            { new: true }
        ).select('-password');
        res.json({ success: true, user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Change password
app.put('/api/auth/change-password', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (user.password !== currentPassword) {
            return res.status(400).json({ error: 'Current password is incorrect' });
        }
        user.password = newPassword;
        await user.save();
        res.json({ success: true, message: 'Password changed successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== SETTINGS ROUTES ====================

// App Settings (GST rate, etc.)
const appSettingsSchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    value: mongoose.Schema.Types.Mixed
});
const AppSetting = mongoose.model('AppSetting', appSettingsSchema);

// Get app settings
app.get('/api/settings', authenticateToken, async (req, res) => {
    try {
        const settings = await AppSetting.find();
        const settingsMap = {};
        settings.forEach(s => {
            settingsMap[s.key] = s.value;
        });
        res.json(settingsMap);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update app setting (Admin only)
app.put('/api/settings/:key', authenticateToken, requireAdmin, async (req, res) => {
    const { value } = req.body;
    try {
        let setting = await AppSetting.findOne({ key: req.params.key });
        if (setting) {
            setting.value = value;
            await setting.save();
        } else {
            setting = new AppSetting({ key: req.params.key, value });
            await setting.save();
        }
        res.json({ success: true, setting });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== MATERIAL ROUTES ====================

app.get('/api/materials', authenticateToken, async (req, res) => {
    try {
        const materials = await Material.find().populate('category_id', 'name');
        res.json(materials);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/materials', authenticateToken, requireAdmin, async (req, res) => {
    const { name, category_id, price_per_unit, unit } = req.body;
    try {
        const newMaterial = new Material({ name, category_id, price_per_unit, unit });
        await newMaterial.save();
        res.json(newMaterial);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/material-categories', authenticateToken, async (req, res) => {
    try {
        const categories = await MaterialCategory.find();
        res.json(categories);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/materials/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await Material.findByIdAndDelete(req.params.id);
        res.json({ message: 'Material deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== WORKER ROUTES ====================

app.get('/api/workers', authenticateToken, async (req, res) => {
    try {
        const workers = await Worker.find();
        res.json(workers);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/workers', authenticateToken, requireAdmin, async (req, res) => {
    const { name, role, daily_wage, phone } = req.body;
    try {
        const newWorker = new Worker({ name, role, daily_wage, phone });
        await newWorker.save();
        res.json(newWorker);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/workers/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await Worker.findByIdAndDelete(req.params.id);
        res.json({ message: 'Worker deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== PROJECT ROUTES ====================

app.get('/api/projects', authenticateToken, async (req, res) => {
    try {
        const projects = await Project.find().sort({ createdAt: -1 });
        res.json(projects);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/projects/:id', authenticateToken, async (req, res) => {
    try {
        const project = await Project.findById(req.params.id);
        if (!project) {
            return res.status(404).json({ error: 'Project not found' });
        }
        res.json(project);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/projects', authenticateToken, async (req, res) => {
    const { project_name, customer_name, area_sqft, status } = req.body;
    try {
        const newProject = new Project({
            project_name,
            customer_name,
            area_sqft,
            status: status || 'Planning',
            createdBy: req.user.id
        });
        await newProject.save();
        res.json(newProject);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get project materials
app.get('/api/projects/:id/materials', authenticateToken, async (req, res) => {
    try {
        const materials = await ProjectMaterial.find({ project_id: req.params.id }).populate('material_id', 'name unit price_per_unit');
        res.json(materials);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Add material to project
app.post('/api/projects/:id/materials', authenticateToken, async (req, res) => {
    const { material_id, quantity, unit_price } = req.body;
    const project_id = req.params.id;
    const total_cost = quantity * unit_price;
    try {
        const newProjectMaterial = new ProjectMaterial({
            project_id,
            material_id,
            quantity,
            unit_price,
            total_cost
        });
        await newProjectMaterial.save();
        res.json(newProjectMaterial);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get project workers
app.get('/api/projects/:id/workers', authenticateToken, async (req, res) => {
    try {
        const workers = await ProjectWorker.find({ project_id: req.params.id }).populate('worker_id', 'name role daily_wage');
        res.json(workers);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Add worker to project
app.post('/api/projects/:id/workers', authenticateToken, async (req, res) => {
    const { worker_id, days, daily_wage } = req.body;
    const project_id = req.params.id;
    const total_wage = days * daily_wage;
    try {
        const newProjectWorker = new ProjectWorker({
            project_id,
            worker_id,
            days,
            daily_wage,
            total_wage
        });
        await newProjectWorker.save();
        res.json(newProjectWorker);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get project costing
app.get('/api/projects/:id/costing', authenticateToken, async (req, res) => {
    try {
        const materials = await ProjectMaterial.find({ project_id: req.params.id }).populate('material_id', 'name unit price_per_unit');
        const workers = await ProjectWorker.find({ project_id: req.params.id }).populate('worker_id', 'name role daily_wage');
        
        let material_cost = 0;
        let labor_cost = 0;
        
        materials.forEach(m => {
            material_cost += m.total_cost || 0;
        });
        
        workers.forEach(w => {
            labor_cost += w.total_wage || 0;
        });
        
        const total_cost = material_cost + labor_cost;
        
        res.json({
            materials,
            workers,
            material_cost,
            labor_cost,
            total_cost
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== QUOTATION ROUTES ====================

app.get('/api/quotations', authenticateToken, async (req, res) => {
    try {
        const quotations = await Quotation.find().populate('project_id', 'project_name customer_name').sort({ createdAt: -1 });
        res.json(quotations);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/quotations/:id', async (req, res) => {
    try {
        const quotation = await Quotation.findById(req.params.id).populate('project_id', 'project_name customer_name area_sqft');
        if (!quotation) {
            return res.status(404).json({ error: 'Quotation not found' });
        }
        
        const materials = await QuotationMaterial.find({ quotation_id: req.params.id }).populate('material_id', 'name unit');
        const workers = await QuotationWorker.find({ quotation_id: req.params.id }).populate('worker_id', 'name role');
        
        res.json({
            ...quotation.toObject(),
            materials,
            workers
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/quotation/generate', authenticateToken, async (req, res) => {
    const { project_id } = req.body;
    
    try {
        const materials = await ProjectMaterial.find({ project_id }).populate('material_id', 'name unit price_per_unit');
        const workers = await ProjectWorker.find({ project_id }).populate('worker_id', 'name role daily_wage');
        
        let material_cost = 0;
        let labor_cost = 0;
        
        materials.forEach(m => {
            material_cost += m.total_cost || 0;
        });
        
        workers.forEach(w => {
            labor_cost += w.total_wage || 0;
        });
        
        const total_cost = material_cost + labor_cost;
        const gst_amount = total_cost * 0.18;
        const grand_total = total_cost + gst_amount;
        
        const quotation_number = 'QTN-' + Date.now().toString().slice(-8);
        
        const newQuotation = new Quotation({
            project_id,
            quotation_number,
            material_cost,
            labor_cost,
            total_cost,
            gst_amount,
            grand_total
        });
        await newQuotation.save();
        
        const quotation_id = newQuotation._id;
        
        for (const m of materials) {
            const qm = new QuotationMaterial({
                quotation_id,
                material_id: m.material_id._id,
                quantity: m.quantity,
                unit_price: m.unit_price,
                total_cost: m.total_cost
            });
            await qm.save();
        }
        
        for (const w of workers) {
            const qw = new QuotationWorker({
                quotation_id,
                worker_id: w.worker_id._id,
                days: w.days,
                daily_wage: w.daily_wage,
                total_cost: w.total_wage
            });
            await qw.save();
        }
        
        res.json({
            id: quotation_id,
            quotation_number,
            material_cost,
            labor_cost,
            total_cost,
            gst_amount,
            grand_total,
            message: 'Quotation generated successfully'
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete project
app.delete('/api/projects/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await Project.findByIdAndDelete(req.params.id);
        // Also delete related project materials and workers
        await ProjectMaterial.deleteMany({ project_id: req.params.id });
        await ProjectWorker.deleteMany({ project_id: req.params.id });
        res.json({ message: 'Project deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete project material
app.delete('/api/projects/:projectId/materials/:materialId', authenticateToken, async (req, res) => {
    try {
        await ProjectMaterial.findByIdAndDelete(req.params.materialId);
        res.json({ message: 'Project material deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete project worker
app.delete('/api/projects/:projectId/workers/:workerId', authenticateToken, async (req, res) => {
    try {
        await ProjectWorker.findByIdAndDelete(req.params.workerId);
        res.json({ message: 'Project worker deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete quotation
app.delete('/api/quotations/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await Quotation.findByIdAndDelete(req.params.id);
        // Also delete related quotation materials and workers
        await QuotationMaterial.deleteMany({ quotation_id: req.params.id });
        await QuotationWorker.deleteMany({ quotation_id: req.params.id });
        res.json({ message: 'Quotation deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== SEED DATA ROUTE (for initial setup) ====================

app.post('/api/seed', async (req, res) => {
    try {
        // Check if admin exists
        const adminExists = await User.findOne({ phone: '1234567890' });
        if (!adminExists) {
            await User.create({
                name: 'Admin',
                phone: '1234567890',
                password: 'admin123',
                role: 'admin'
            });
            
            await MaterialCategory.create([
                { name: 'Cement', description: 'All types of cement' },
                { name: 'Steel', description: 'Steel bars and rods' },
                { name: 'Bricks', description: 'Bricks and blocks' },
                { name: 'Sand', description: 'Sand and aggregates' },
                { name: 'Aggregate', description: 'Stone aggregates' },
                { name: 'Concrete', description: 'Ready mix concrete' },
                { name: 'Paint', description: 'Paints and coatings' },
                { name: 'Flooring', description: 'Flooring materials' },
                { name: 'Electrical', description: 'Electrical materials' },
                { name: 'Plumbing', description: 'Plumbing materials' }
            ]);
            
            res.json({ message: 'Seed data created successfully' });
        } else {
            res.json({ message: 'Seed data already exists' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== START SERVER ====================

const server = app.listen(PORT, () => {
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║           Builder Site API Server Started                ║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log(`║  Server:    http://localhost:${PORT}                        ║`);
    console.log(`║  Health:    http://localhost:${PORT}/health                ║`);
    console.log(`║  Environment: ${process.env.NODE_ENV || 'development'}                            ║`);
    console.log('╚════════════════════════════════════════════════════════════╝');
});

// Graceful Shutdown
const gracefulShutdown = async (signal) => {
    console.log(`\n${signal} received. Starting graceful shutdown...`);
    
    server.close(async () => {
        console.log('HTTP server closed.');
        
        try {
            await mongoose.connection.close();
            console.log('MongoDB connection closed.');
            process.exit(0);
        } catch (err) {
            console.error('Error during shutdown:', err);
            process.exit(1);
        }
    });
    
    // Force shutdown after 10 seconds
    setTimeout(() => {
        console.error('Forced shutdown after timeout.');
        process.exit(1);
    }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Unhandled Promise Rejections
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Uncaught Exceptions
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    process.exit(1);
});
