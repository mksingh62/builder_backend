const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'house_construction_secret_key_2024';

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error('MongoDB Connection Error:', err));

// ==================== MODELS ====================

// User Model
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    phone: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'staff', 'customer'], default: 'customer' },
    profilePhoto: String,
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
    customer_phone: String,
    site_address: String,
    area_sqft: { type: Number, default: 0 },
    expected_duration: String,
    status: { type: String, enum: ['Planning', 'In Progress', 'Completed', 'Pending'], default: 'Planning' },
    start_date: Date,
    end_date: Date,
    total_cost: { type: Number, default: 0 },
    paid_amount: { type: Number, default: 0 },
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

// ========== NEW MODELS FOR ADVANCED FLOW ==========

// Construction Stages Master
const stageMasterSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: String,
    order: { type: Number, default: 0 }
});
const StageMaster = mongoose.model('StageMaster', stageMasterSchema);

// Project Stage (stage-wise tracking)
const projectStageSchema = new mongoose.Schema({
    project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    stage_name: String,
    stage_order: Number,
    status: { type: String, enum: ['Pending', 'In Progress', 'Completed'], default: 'Pending' },
    start_date: Date,
    end_date: Date,
    material_cost: { type: Number, default: 0 },
    labor_cost: { type: Number, default: 0 },
    total_cost: { type: Number, default: 0 }
});
const ProjectStage = mongoose.model('ProjectStage', projectStageSchema);

// Stage Materials
const stageMaterialSchema = new mongoose.Schema({
    project_stage_id: { type: mongoose.Schema.Types.ObjectId, ref: 'ProjectStage' },
    project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    material_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Material' },
    material_name: String,
    quantity: { type: Number, default: 0 },
    unit_price: { type: Number, default: 0 },
    total_cost: { type: Number, default: 0 }
});
const StageMaterial = mongoose.model('StageMaterial', stageMaterialSchema);

// Stage Workers
const stageWorkerSchema = new mongoose.Schema({
    project_stage_id: { type: mongoose.Schema.Types.ObjectId, ref: 'ProjectStage' },
    project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    worker_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Worker' },
    worker_name: String,
    worker_role: String,
    days: { type: Number, default: 0 },
    daily_wage: { type: Number, default: 0 },
    total_cost: { type: Number, default: 0 }
});
const StageWorker = mongoose.model('StageWorker', stageWorkerSchema);

// Daily Work Entry
const dailyEntrySchema = new mongoose.Schema({
    project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    date: { type: Date, default: Date.now },
    workers_present: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Worker' }],
    materials_used: [{
        material_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Material' },
        material_name: String,
        quantity: Number,
        cost: Number
    }],
    extra_expenses: { type: Number, default: 0 },
    expense_description: String,
    total_daily_cost: { type: Number, default: 0 },
    notes: String
});
const DailyEntry = mongoose.model('DailyEntry', dailyEntrySchema);

// Payment Milestone
const paymentSchema = new mongoose.Schema({
    project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    quotation_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Quotation' },
    payment_number: { type: Number, default: 1 },
    milestone_name: String,
    amount: { type: Number, required: true },
    paid_amount: { type: Number, default: 0 },
    due_date: Date,
    status: { type: String, enum: ['Pending', 'Partial', 'Paid', 'Overdue'], default: 'Pending' },
    payment_date: Date,
    payment_mode: String,
    transaction_id: String
});
const Payment = mongoose.model('Payment', paymentSchema);

// Document
const documentSchema = new mongoose.Schema({
    project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    document_type: { type: String, enum: ['Site Photo', 'Bill', 'Invoice', 'Material Proof', 'Contract', 'Other'] },
    file_name: String,
    file_url: String,
    description: String,
    uploaded_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now }
});
const Document = mongoose.model('Document', documentSchema);

// Quotation Version
const quotationVersionSchema = new mongoose.Schema({
    project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    version: { type: Number, default: 1 },
    version_name: { type: String, default: 'v1' },
    material_cost: { type: Number, default: 0 },
    labor_cost: { type: Number, default: 0 },
    total_cost: { type: Number, default: 0 },
    gst_amount: { type: Number, default: 0 },
    grand_total: { type: Number, default: 0 },
    status: { type: String, enum: ['Draft', 'Sent', 'Approved', 'Rejected', 'Revised'], default: 'Draft' },
    approval_status: { type: String, enum: ['Pending', 'Approved', 'Rejected', 'Modification Requested'], default: 'Pending' },
    notes: String,
    createdAt: { type: Date, default: Date.now }
});
const QuotationVersion = mongoose.model('QuotationVersion', quotationVersionSchema);

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

// ==================== MULTER CONFIGURATION ====================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = './uploads/profiles/';
        const fs = require('fs');
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        cb(null, req.user.id + '-' + Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Only images (jpg, jpeg, png) are allowed!'));
    }
});

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
                role: user.role,
                profilePhoto: user.profilePhoto
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

// Update profile photo
app.put('/api/auth/profile/photo', authenticateToken, upload.single('photo'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'Please upload an image' });
        }

        const photoUrl = `/uploads/profiles/${req.file.filename}`;
        const user = await User.findByIdAndUpdate(
            req.user.id,
            { profilePhoto: photoUrl },
            { new: true }
        ).select('-password');

        res.json({ success: true, profilePhoto: photoUrl, user });
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
        // Clear existing data first
        await User.deleteMany({});
        await MaterialCategory.deleteMany({});
        await Material.deleteMany({});
        await Worker.deleteMany({});
        await Project.deleteMany({});
        await ProjectMaterial.deleteMany({});
        await ProjectWorker.deleteMany({});
        await Quotation.deleteMany({});
        await StageMaster.deleteMany({});
        await ProjectStage.deleteMany({});
        await StageMaterial.deleteMany({});
        await StageWorker.deleteMany({});
        await DailyEntry.deleteMany({});
        await Payment.deleteMany({});
        await Document.deleteMany({});
        await QuotationVersion.deleteMany({});
        await AppSetting.deleteMany({});

        // Create Users
        const admin = await User.create({ name: 'Admin', phone: '1234567890', password: 'admin123', role: 'admin' });
        const staff = await User.create({ name: 'Rahul Sharma', phone: '9876543210', password: 'staff123', role: 'staff' });
        const customer = await User.create({ name: 'Amit Patel', phone: '9988776655', password: 'user123', role: 'customer' });
        const customer2 = await User.create({ name: 'Suresh Kumar', phone: '9977665544', password: 'user123', role: 'customer' });

        // Create Material Categories
        const categories = await MaterialCategory.create([
            { name: 'Cement', description: 'All types of cement' },
            { name: 'Steel', description: 'Steel bars and rods' },
            { name: 'Bricks', description: 'Bricks and blocks' },
            { name: 'Sand', description: 'Sand and aggregates' },
            { name: 'Aggregate', description: 'Stone aggregates' },
            { name: 'Paint', description: 'Paints and coatings' },
            { name: 'Flooring', description: 'Flooring materials' },
            { name: 'Electrical', description: 'Electrical materials' },
            { name: 'Plumbing', description: 'Plumbing materials' }
        ]);

        // Create Materials
        const cementCat = categories.find(c => c.name === 'Cement');
        const steelCat = categories.find(c => c.name === 'Steel');
        const bricksCat = categories.find(c => c.name === 'Bricks');
        const sandCat = categories.find(c => c.name === 'Sand');
        const paintCat = categories.find(c => c.name === 'Paint');

        const materials = await Material.create([
            { name: 'OPC 53 Grade Cement', category_id: cementCat._id, price_per_unit: 380, unit: 'bag' },
            { name: 'PPC Cement', category_id: cementCat._id, price_per_unit: 350, unit: 'bag' },
            { name: 'TMT Steel 12mm', category_id: steelCat._id, price_per_unit: 65, unit: 'kg' },
            { name: 'TMT Steel 16mm', category_id: steelCat._id, price_per_unit: 68, unit: 'kg' },
            { name: 'Red Bricks', category_id: bricksCat._id, price_per_unit: 8, unit: 'piece' },
            { name: 'AAC Blocks', category_id: bricksCat._id, price_per_unit: 45, unit: 'piece' },
            { name: 'River Sand', category_id: sandCat._id, price_per_unit: 45, unit: 'cft' },
            { name: 'M Sand', category_id: sandCat._id, price_per_unit: 35, unit: 'cft' },
            { name: 'Interior Paint', category_id: paintCat._id, price_per_unit: 280, unit: 'liter' },
            { name: 'Exterior Paint', category_id: paintCat._id, price_per_unit: 320, unit: 'liter' }
        ]);

        // Create Workers
        const workers = await Worker.create([
            { name: 'Mohan Singh', role: 'Mason', daily_wage: 800 },
            { name: 'Ramesh Kumar', role: 'Mason', daily_wage: 750 },
            { name: 'Sanjay Sharma', role: 'Carpenter', daily_wage: 700 },
            { name: 'Kamal Ahmed', role: 'Electrician', daily_wage: 650 },
            { name: 'Vijay Plumber', role: 'Plumber', daily_wage: 600 },
            { name: 'Dinesh Kumar', role: 'Helper', daily_wage: 450 },
            { name: 'Raj Kumar', role: 'Painter', daily_wage: 550 }
        ]);

        // Create Construction Stages Master
        const stages = await StageMaster.create([
            { name: 'Foundation', description: 'Foundation work', order: 1 },
            { name: 'Structure', description: 'Pillar and slab work', order: 2 },
            { name: 'Brick Work', description: 'Wall construction', order: 3 },
            { name: 'Plaster', description: 'Wall plastering', order: 4 },
            { name: 'Flooring', description: 'Floor laying', order: 5 },
            { name: 'Finishing', description: 'Paint and final work', order: 6 }
        ]);

        // Create Projects
        const project1 = await Project.create({
            project_name: 'Sharma Villa',
            customer_name: 'Amit Patel',
            customer_phone: '9988776655',
            site_address: '123, MG Road, Mumbai',
            area_sqft: 2500,
            status: 'In Progress',
            start_date: new Date('2024-01-15'),
            expected_duration: '6 months',
            createdBy: admin._id
        });

        const project2 = await Project.create({
            project_name: 'Kumar Residence',
            customer_name: 'Suresh Kumar',
            customer_phone: '9977665544',
            site_address: '456, Andheri East, Mumbai',
            area_sqft: 1800,
            status: 'Planning',
            start_date: new Date('2024-03-01'),
            expected_duration: '5 months',
            createdBy: admin._id
        });

        // Create Project Stages for Project 1
        const foundationStage = await ProjectStage.create({
            project_id: project1._id,
            stage_name: 'Foundation',
            stage_order: 1,
            status: 'Completed',
            start_date: new Date('2024-01-15'),
            end_date: new Date('2024-02-15'),
            material_cost: 150000,
            labor_cost: 50000,
            total_cost: 200000
        });

        const structureStage = await ProjectStage.create({
            project_id: project1._id,
            stage_name: 'Structure',
            stage_order: 2,
            status: 'In Progress',
            start_date: new Date('2024-02-16')
        });

        // Create Payments for Project 1
        await Payment.create([
            { project_id: project1._id, milestone_name: 'Advance Payment', amount: 200000, paid_amount: 200000, status: 'Paid', payment_date: new Date('2024-01-10') },
            { project_id: project1._id, milestone_name: 'Foundation Complete', amount: 200000, paid_amount: 150000, status: 'Partial', due_date: new Date('2024-02-20') },
            { project_id: project1._id, milestone_name: 'Structure Complete', amount: 300000, status: 'Pending', due_date: new Date('2024-04-01') }
        ]);

        // Create Quotation with Version
        const quotation = await Quotation.create({
            project_id: project1._id,
            quotation_number: 'QT-2024-001',
            material_cost: 500000,
            labor_cost: 200000,
            total_cost: 700000,
            gst_amount: 126000,
            grand_total: 826000,
            status: 'Approved'
        });

        // Create Quotation Versions
        await QuotationVersion.create([
            { project_id: project1._id, version: 1, version_name: 'v1', material_cost: 500000, labor_cost: 200000, total_cost: 700000, gst_amount: 126000, grand_total: 826000, status: 'Approved', approval_status: 'Approved' },
            { project_id: project1._id, version: 2, version_name: 'v2', material_cost: 550000, labor_cost: 220000, total_cost: 770000, gst_amount: 138600, grand_total: 908600, status: 'Revised', approval_status: 'Pending' }
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
            success: true,
            message: 'Complete seed data created!',
            users: { admin: '1234567890/admin123', staff: '9876543210/staff123', customer: '9988776655/user123' },
            stats: { materials: materials.length, workers: workers.length, stages: stages.length, projects: 2, payments: 3 }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== NEW ADVANCED FEATURES ROUTES ====================

// Stage Master Routes
app.get('/api/stages', authenticateToken, async (req, res) => {
    try {
        const stages = await StageMaster.find().sort({ order: 1 });
        res.json(stages);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/stages', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const stage = new StageMaster(req.body);
        await stage.save();
        res.status(201).json(stage);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/stages/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const stage = await StageMaster.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(stage);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/stages/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await StageMaster.findByIdAndDelete(req.params.id);
        res.json({ message: 'Stage deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Project Stage Routes
app.get('/api/projects/:id/stages', authenticateToken, async (req, res) => {
    try {
        const projectStages = await ProjectStage.find({ project_id: req.params.id })
            .sort({ stage_order: 1 });
        res.json(projectStages);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/projects/:id/stages', authenticateToken, async (req, res) => {
    try {
        const projectStage = new ProjectStage({
            project_id: req.params.id,
            ...req.body
        });
        await projectStage.save();
        res.status(201).json(projectStage);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/projects/:projectId/stages/:stageId', authenticateToken, async (req, res) => {
    try {
        const projectStage = await ProjectStage.findByIdAndUpdate(
            req.params.stageId,
            req.body,
            { new: true }
        );
        res.json(projectStage);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Daily Entry Routes
app.get('/api/projects/:id/daily-entries', authenticateToken, async (req, res) => {
    try {
        const dailyEntries = await DailyEntry.find({ project_id: req.params.id })
            .sort({ date: -1 });
        res.json(dailyEntries);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/projects/:id/daily-entries', authenticateToken, async (req, res) => {
    try {
        const dailyEntry = new DailyEntry({
            project_id: req.params.id,
            ...req.body
        });

        // Calculate total daily cost
        let totalCost = dailyEntry.extra_expenses || 0;

        // Add material costs
        for (const material of dailyEntry.materials_used) {
            totalCost += material.cost || 0;
        }

        dailyEntry.total_daily_cost = totalCost;
        await dailyEntry.save();

        res.status(201).json(dailyEntry);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/daily-entries/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await DailyEntry.findByIdAndDelete(req.params.id);
        res.json({ message: 'Daily entry deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Payment Routes
app.get('/api/projects/:id/payments', authenticateToken, async (req, res) => {
    try {
        const payments = await Payment.find({ project_id: req.params.id })
            .sort({ due_date: 1 });
        res.json(payments);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/projects/:id/payments', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const payment = new Payment({
            project_id: req.params.id,
            ...req.body
        });
        await payment.save();
        res.status(201).json(payment);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/payments/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const payment = await Payment.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(payment);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/payments/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await Payment.findByIdAndDelete(req.params.id);
        res.json({ message: 'Payment deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Document Routes
app.get('/api/projects/:id/documents', authenticateToken, async (req, res) => {
    try {
        const documents = await Document.find({ project_id: req.params.id })
            .sort({ createdAt: -1 });
        res.json(documents);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/projects/:id/documents', authenticateToken, async (req, res) => {
    try {
        const document = new Document({
            project_id: req.params.id,
            ...req.body
        });
        await document.save();
        res.status(201).json(document);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/documents/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await Document.findByIdAndDelete(req.params.id);
        res.json({ message: 'Document deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
