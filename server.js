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
            // Create Users
            const admin = await User.create({
                name: 'Admin',
                phone: '1234567890',
                password: 'admin123',
                role: 'admin'
            });
            
            const staff = await User.create({
                name: 'Mohit',
                phone: '9876543210',
                password: 'staff123',
                role: 'staff'
            });
            
            const customer = await User.create({
                name: 'Ajay',
                phone: '9988776655',
                password: 'user123',
                role: 'customer'
            });
            
            const customer2 = await User.create({
                name: 'Nikhil',
                phone: '9977665544',
                password: 'user123',
                role: 'customer'
            });
            
            // Create Material Categories
            const categories = await MaterialCategory.create([
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
            
            // Get category IDs
            const cementCat = categories.find(c => c.name === 'Cement');
            const steelCat = categories.find(c => c.name === 'Steel');
            const bricksCat = categories.find(c => c.name === 'Bricks');
            const sandCat = categories.find(c => c.name === 'Sand');
            const paintCat = categories.find(c => c.name === 'Paint');
            
            // Create Materials
            const materials = await Material.create([
                { name: 'Portland Cement (OPC 53 Grade)', category_id: cementCat._id, price_per_unit: 380, unit: 'bag' },
                { name: 'Portland Cement (PPC)', category_id: cementCat._id, price_per_unit: 350, unit: 'bag' },
                { name: 'White Cement', category_id: cementCat._id, price_per_unit: 520, unit: 'bag' },
                { name: 'TMT Steel 12mm', category_id: steelCat._id, price_per_unit: 65, unit: 'kg' },
                { name: 'TMT Steel 16mm', category_id: steelCat._id, price_per_unit: 68, unit: 'kg' },
                { name: 'TMT Steel 20mm', category_id: steelCat._id, price_per_unit: 70, unit: 'kg' },
                { name: 'TMT Steel 25mm', category_id: steelCat._id, price_per_unit: 72, unit: 'kg' },
                { name: 'Red Bricks', category_id: bricksCat._id, price_per_unit: 8, unit: 'piece' },
                { name: 'AAC Blocks', category_id: bricksCat._id, price_per_unit: 45, unit: 'piece' },
                { name: 'Fly Ash Bricks', category_id: bricksCat._id, price_per_unit: 6, unit: 'piece' },
                { name: 'River Sand', category_id: sandCat._id, price_per_unit: 45, unit: 'cft' },
                { name: 'M Sand', category_id: sandCat._id, price_per_unit: 35, unit: 'cft' },
                { name: 'Aggregate 20mm', category_id: sandCat._id, price_per_unit: 28, unit: 'cft' },
                { name: 'Aggregate 10mm', category_id: sandCat._id, price_per_unit: 25, unit: 'cft' },
                { name: 'Interior Paint (Asian)', category_id: paintCat._id, price_per_unit: 280, unit: 'liter' },
                { name: 'Exterior Paint (Asian)', category_id: paintCat._id, price_per_unit: 320, unit: 'liter' },
                { name: 'Enamel Paint', category_id: paintCat._id, price_per_unit: 250, unit: 'liter' }
            ]);
            
            // Create Workers
            const workers = await Worker.create([
                { name: 'Mohan Singh', role: 'Mason', daily_wage: 800, phone: '911234567890' },
                { name: 'Ramesh Kumar', role: 'Mason', daily_wage: 750, phone: '911234567891' },
                { name: 'Sanjay Sharma', role: 'Carpenter', daily_wage: 700, phone: '911234567892' },
                { name: 'Kamal Ahmed', role: 'Electrician', daily_wage: 650, phone: '911234567893' },
                { name: 'Vijay Plumber', role: 'Plumber', daily_wage: 600, phone: '911234567894' },
                { name: 'Dinesh Kumar', role: 'Helper', daily_wage: 450, phone: '911234567895' },
                { name: 'Bablu Singh', role: 'Helper', daily_wage: 450, phone: '911234567896' },
                { name: 'Raj Kumar', role: 'Painter', daily_wage: 550, phone: '911234567897' }
            ]);
            
            // Create Projects
            const project1 = await Project.create({
                project_name: 'Sharma Villa',
                customer_name: 'Amit Patel',
                area_sqft: 2500,
                status: 'In Progress',
                start_date: new Date('2024-01-15'),
                end_date: new Date('2024-06-30'),
                createdBy: admin._id
            });
            
            const project2 = await Project.create({
                project_name: 'Kumar Residence',
                customer_name: 'Suresh Kumar',
                area_sqft: 1800,
                status: 'Planning',
                start_date: new Date('2024-03-01'),
                end_date: new Date('2024-08-31'),
                createdBy: admin._id
            });
            
            const project3 = await Project.create({
                project_name: 'Gupta Farm House',
                customer_name: 'Rajesh Gupta',
                area_sqft: 3500,
                status: 'Completed',
                start_date: new Date('2023-06-01'),
                end_date: new Date('2023-12-31'),
                createdBy: admin._id
            });
            
            // Add materials to project 1
            const cement = materials.find(m => m.name.includes('OPC 53'));
            const steel12 = materials.find(m => m.name.includes('TMT Steel 12mm'));
            const bricks = materials.find(m => m.name === 'Red Bricks');
            const sand = materials.find(m => m.name === 'River Sand');
            
            await ProjectMaterial.create([
                { project_id: project1._id, material_id: cement._id, quantity: 150, unit_price: cement.price_per_unit, total_cost: 150 * cement.price_per_unit },
                { project_id: project1._id, material_id: steel12._id, quantity: 800, unit_price: steel12.price_per_unit, total_cost: 800 * steel12.price_per_unit },
                { project_id: project1._id, material_id: bricks._id, quantity: 5000, unit_price: bricks.price_per_unit, total_cost: 5000 * bricks.price_per_unit },
                { project_id: project1._id, material_id: sand._id, quantity: 200, unit_price: sand.price_per_unit, total_cost: 200 * sand.price_per_unit }
            ]);
            
            // Add workers to project 1
            const mason1 = workers.find(w => w.name === 'Mohan Singh');
            const mason2 = workers.find(w => w.name === 'Ramesh Kumar');
            const helper1 = workers.find(w => w.name === 'Dinesh Kumar');
            
            await ProjectWorker.create([
                { project_id: project1._id, worker_id: mason1._id, days: 30, daily_wage: mason1.daily_wage, total_wage: 30 * mason1.daily_wage },
                { project_id: project1._id, worker_id: mason2._id, days: 25, daily_wage: mason2.daily_wage, total_wage: 25 * mason2.daily_wage },
                { project_id: project1._id, worker_id: helper1._id, days: 30, daily_wage: helper1.daily_wage, total_wage: 30 * helper1.daily_wage }
            ]);
            
            // Create Quotations
            await Quotation.create([
                {
                    project_id: project1._id,
                    quotation_number: 'QT-2024-001',
                    material_cost: 450000,
                    labor_cost: 180000,
                    total_cost: 630000,
                    gst_amount: 113400,
                    grand_total: 743400,
                    status: 'Approved'
                },
                {
                    project_id: project2._id,
                    quotation_number: 'QT-2024-002',
                    material_cost: 320000,
                    labor_cost: 120000,
                    total_cost: 440000,
                    gst_amount: 79200,
                    grand_total: 519200,
                    status: 'Pending'
                }
            ]);
            
            // Create App Settings
            await AppSetting.create([
                { key: 'gst_rate', value: 18 },
                { key: 'company_name', value: 'Builder Site Construction' },
                { key: 'company_address', value: '123 Construction Road, Mumbai-400001' },
                { key: 'company_phone', value: '+91-1234567890' },
                { key: 'company_email', value: 'info@buildersite.com' }
            ]);
            
            res.json({ 
                message: 'Complete seed data created successfully',
                users: { admin: '1234567890 / admin123', staff: '9876543210 / staff123', customer: '9988776655 / user123' },
                materials: materials.length,
                workers: workers.length,
                projects: 3,
                quotations: 2
            });
        } else {
            res.json({ message: 'Seed data already exists' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== START SERVER ====================

const server = app.listen(PORT, '0.0.0.0', () => {
    const vercelUrl = process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : `http://localhost:${PORT}`;
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║           Builder Site API Server Started                ║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log(`║  Server:    ${vercelUrl}                        ║`);
    console.log(`║  Health:    ${vercelUrl}/health                    ║`);
    console.log(`║  API Base:  ${vercelUrl}/api                      ║`);
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
