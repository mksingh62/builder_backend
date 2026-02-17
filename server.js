const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const cron = require('node-cron');
const fs = require('fs');

const config = require('./config');
const { authenticateToken, requireAdmin } = require('./middleware/auth');
const errorHandler = require('./middleware/errorHandler');
const { authLimiter } = require('./middleware/rateLimit');
const { validatePhone, validatePassword } = require('./utils/validation');
const logger = require('./utils/logger');

// Check if we're in a serverless environment (Vercel, AWS Lambda, etc.)
const isServerless = process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || !fs.existsSync || typeof __dirname === 'undefined';

const app = express();
// CORS - allow all origins for now (restrict in production)
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true
}));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));
// Static file serving only in non-serverless environments
if (!isServerless && fs.existsSync && typeof __dirname !== 'undefined') {
    try {
        const uploadsPath = path.join(__dirname, 'uploads');
        if (fs.existsSync(uploadsPath)) {
            app.use('/uploads', express.static(uploadsPath));
        }
    } catch (e) {
        // Ignore if uploads directory doesn't exist (serverless)
    }
}

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || config.mongodbUri || '')
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
// Only add createdAt index, phone already has unique index
userSchema.index({ createdAt: -1 });
const User = mongoose.models.User || mongoose.model('User', userSchema);

// Material Category Model
const materialCategorySchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: String
});
const MaterialCategory = mongoose.models.MaterialCategory || mongoose.model('MaterialCategory', materialCategorySchema);

// Material Model
const materialSchema = new mongoose.Schema({
    name: { type: String, required: true },
    category_id: { type: mongoose.Schema.Types.ObjectId, ref: 'MaterialCategory' },
    price_per_unit: { type: Number, required: true },
    unit: { type: String, default: 'unit' },
    current_stock: { type: Number, default: 0 },
    total_stock: { type: Number, default: 100 },
    createdAt: { type: Date, default: Date.now }
});
const Material = mongoose.models.Material || mongoose.model('Material', materialSchema);

// Worker Model
const workerSchema = new mongoose.Schema({
    name: { type: String, required: true },
    role: { type: String, default: 'Worker' },
    daily_wage: { type: Number, required: true },
    phone_number: String,
    location: String,
    createdAt: { type: Date, default: Date.now }
});
const Worker = mongoose.models.Worker || mongoose.model('Worker', workerSchema);

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
projectSchema.index({ createdBy: 1 });
projectSchema.index({ status: 1 });
projectSchema.index({ createdAt: -1 });
projectSchema.index({ customer_phone: 1 });
const Project = mongoose.models.Project || mongoose.model('Project', projectSchema);

// Project Material Model
const projectMaterialSchema = new mongoose.Schema({
    project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    material_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Material' },
    quantity: { type: Number, default: 0 },
    unit_price: { type: Number, default: 0 },
    total_cost: { type: Number, default: 0 }
});
projectMaterialSchema.index({ project_id: 1 });
const ProjectMaterial = mongoose.models.ProjectMaterial || mongoose.model('ProjectMaterial', projectMaterialSchema);

// Project Worker Model
const projectWorkerSchema = new mongoose.Schema({
    project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    worker_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Worker' },
    days: { type: Number, default: 0 },
    daily_wage: { type: Number, default: 0 },
    total_wage: { type: Number, default: 0 }
});
projectWorkerSchema.index({ project_id: 1 });
const ProjectWorker = mongoose.models.ProjectWorker || mongoose.model('ProjectWorker', projectWorkerSchema);

// Quotation Model
const quotationSchema = new mongoose.Schema({
    project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    quotation_number: { type: String, required: true },
    material_cost: { type: Number, default: 0 },
    labor_cost: { type: Number, default: 0 },
    total_cost: { type: Number, default: 0 },
    gst_rate: { type: Number, default: 18 },
    gst_amount: { type: Number, default: 0 },
    grand_total: { type: Number, default: 0 },
    status: { type: String, enum: ['Pending', 'Approved', 'Rejected'], default: 'Pending' },
    createdAt: { type: Date, default: Date.now }
});
quotationSchema.index({ project_id: 1 });
quotationSchema.index({ createdAt: -1 });
const Quotation = mongoose.models.Quotation || mongoose.model('Quotation', quotationSchema);

// ========== NEW MODELS FOR ADVANCED FLOW ==========

// Construction Stages Master
const stageMasterSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: String,
    order: { type: Number, default: 0 }
});
const StageMaster = mongoose.models.StageMaster || mongoose.model('StageMaster', stageMasterSchema);

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
projectStageSchema.index({ project_id: 1, stage_order: 1 });
const ProjectStage = mongoose.models.ProjectStage || mongoose.model('ProjectStage', projectStageSchema);

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
const StageMaterial = mongoose.models.StageMaterial || mongoose.model('StageMaterial', stageMaterialSchema);

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
const StageWorker = mongoose.models.StageWorker || mongoose.model('StageWorker', stageWorkerSchema);

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
const DailyEntry = mongoose.models.DailyEntry || mongoose.model('DailyEntry', dailyEntrySchema);

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
paymentSchema.index({ project_id: 1 });
paymentSchema.index({ due_date: 1 });
const Payment = mongoose.models.Payment || mongoose.model('Payment', paymentSchema);

// Document
const documentSchema = new mongoose.Schema({
    project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    document_type: { type: String, enum: ['Site Photo', 'Bill', 'Invoice', 'Material Proof', 'Contract', 'Other'], default: 'Other' },
    file_name: String,
    file_url: String,
    file_size: Number,
    description: String,
    uploaded_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now }
});
documentSchema.index({ project_id: 1, createdAt: -1 });
const Document = mongoose.models.Document || mongoose.model('Document', documentSchema);

// Notification Model
const notificationSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['payment_reminder', 'stage_complete', 'project_update', 'payment_received', 'material_low', 'general'], required: true },
    title: { type: String, required: true },
    message: { type: String, required: true },
    related_id: mongoose.Schema.Types.ObjectId,
    related_type: { type: String, enum: ['project', 'payment', 'material', 'worker', null] },
    read: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});
notificationSchema.index({ user_id: 1, read: 1, createdAt: -1 });
const Notification = mongoose.models.Notification || mongoose.model('Notification', notificationSchema);

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
const QuotationVersion = mongoose.models.QuotationVersion || mongoose.model('QuotationVersion', quotationVersionSchema);

// Quotation Material Model
const quotationMaterialSchema = new mongoose.Schema({
    quotation_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Quotation' },
    material_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Material' },
    quantity: Number,
    unit_price: Number,
    total_cost: Number
});
const QuotationMaterial = mongoose.models.QuotationMaterial || mongoose.model('QuotationMaterial', quotationMaterialSchema);

// Quotation Worker Model
const quotationWorkerSchema = new mongoose.Schema({
    quotation_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Quotation' },
    worker_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Worker' },
    days: Number,
    daily_wage: Number,
    total_cost: Number
});
const QuotationWorker = mongoose.models.QuotationWorker || mongoose.model('QuotationWorker', quotationWorkerSchema);

// ==================== MULTER CONFIGURATION ====================
// Memory storage for all uploads (serverless-compatible)
// For Vercel/serverless, we can't use disk storage, so we use memory and store as base64
const profileStorage = multer.memoryStorage();
const documentStorage = multer.memoryStorage(); // Changed to memory for serverless compatibility

// Document upload (multipart) - using memory storage for serverless compatibility
const documentUpload = multer({
    storage: documentStorage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|pdf|doc|docx|xls|xlsx/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (extname && mimetype) {
            return cb(null, true);
        }
        cb(new Error('Invalid file type. Only images, PDFs, and Office documents allowed.'));
    }
});

// Profile photo upload (memory)
const upload = multer({
    storage: profileStorage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|webp/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

        if (mimetype || extname) {
            return cb(null, true);
        }
        cb(new Error('Only images (jpg, jpeg, png, webp) are allowed!'));
    }
});

// ==================== AUTH ROUTES ====================

// Login
app.post('/api/auth/login', authLimiter, async (req, res, next) => {
    try {
        const { phone, password } = req.body;
        if (!phone || !password) {
            return res.status(400).json({ success: false, message: 'Phone and password required' });
        }
        if (!validatePhone(phone)) {
            return res.status(400).json({ success: false, message: 'Invalid phone number format' });
        }
        const user = await User.findOne({ phone });
        if (!user) {
            return res.status(401).json({ success: false, message: 'User not found' });
        }
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(401).json({ success: false, message: 'Invalid password' });
        }
        const token = jwt.sign(
            { id: user._id, phone: user.phone, role: user.role },
            config.jwtSecret,
            { expiresIn: config.jwtExpiresIn }
        );
        res.json({
            success: true,
            token,
            user: { id: user._id, name: user.name, phone: user.phone, role: user.role }
        });
    } catch (err) {
        next(err);
    }
});

// Register
app.post('/api/auth/register', authLimiter, async (req, res, next) => {
    try {
        const { name, phone, password, role } = req.body;
        if (!name || !phone || !password) {
            return res.status(400).json({ success: false, message: 'Name, phone and password required' });
        }
        if (!validatePhone(phone)) {
            return res.status(400).json({ success: false, message: 'Invalid phone number format' });
        }
        if (!validatePassword(password)) {
            return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
        }
        const hashed = await bcrypt.hash(password, 10);
        const newUser = new User({ name, phone, password: hashed, role: role || 'customer' });
        await newUser.save();
        res.status(201).json({ success: true, id: newUser._id, message: 'User registered successfully' });
    } catch (err) {
        next(err);
    }
});

// Get current user profile
app.get('/api/auth/profile', authenticateToken, async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json(user);
    } catch (err) { next(err); }
});

// Update user profile
app.put('/api/auth/profile', authenticateToken, async (req, res, next) => {
    try {
        const { name, phone } = req.body;
        const user = await User.findByIdAndUpdate(req.user.id, { name, phone }, { new: true }).select('-password');
        res.json({ success: true, user });
    } catch (err) { next(err); }
});

// Update profile photo
app.put('/api/auth/profile/photo', authenticateToken, (req, res, next) => {
    upload.single('photo')(req, res, async (err) => {
        if (err instanceof multer.MulterError) {
            return res.status(400).json({ success: false, message: `Upload error: ${err.message}` });
        } else if (err) {
            return res.status(400).json({ success: false, message: `Upload error: ${err.message}` });
        }

        try {
            if (!req.file) {
                return res.status(400).json({ success: false, message: 'Please upload an image' });
            }

            // Convert buffer to Base64 data URL
            const base64Image = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;

            const user = await User.findByIdAndUpdate(
                req.user.id,
                { profilePhoto: base64Image },
                { new: true }
            ).select('-password');

            res.json({ success: true, profilePhoto: base64Image, user });
        } catch (err) {
            next(err);
        }
    });
});

// Change password
app.put('/api/auth/change-password', authenticateToken, async (req, res, next) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        const valid = await bcrypt.compare(currentPassword, user.password);
        if (!valid) {
            return res.status(400).json({ success: false, message: 'Current password is incorrect' });
        }
        if (String(newPassword).length < 6) {
            return res.status(400).json({ success: false, message: 'New password must be at least 6 characters' });
        }
        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();
        res.json({ success: true, message: 'Password changed successfully' });
    } catch (err) {
        next(err);
    }
});

// ==================== SETTINGS ROUTES ====================

// App Settings (GST rate, etc.)
const appSettingsSchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    value: mongoose.Schema.Types.Mixed
});
const AppSetting = mongoose.models.AppSetting || mongoose.model('AppSetting', appSettingsSchema);

// Get app settings
app.get('/api/settings', authenticateToken, async (req, res, next) => {
    try {
        const settings = await AppSetting.find();
        const settingsMap = {};
        settings.forEach(s => {
            settingsMap[s.key] = s.value;
        });
        res.json(settingsMap);
    } catch (err) {
        next(err);
    }
});

// Update app setting (Admin only)
app.put('/api/settings/:key', authenticateToken, requireAdmin, async (req, res, next) => {
    try {
        const { value } = req.body;
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
        next(err);
    }
});

// ==================== PROJECT ROUTES ====================

app.get('/api/projects', authenticateToken, async (req, res, next) => {
    try {
        const page = parseInt(req.query.page || '1', 10);
        const limit = parseInt(req.query.limit || '50', 10);
        const skip = (page - 1) * limit;
        const statusFilter = req.query.status;
        const sortBy = req.query.sort || '-createdAt';

        let query = req.user.role === 'customer' ? { customer_phone: req.user.phone } : {};
        if (statusFilter && statusFilter !== 'All') {
            query.status = statusFilter;
        }

        const total = await Project.countDocuments(query);
        let sortQuery = {};
        if (sortBy.startsWith('-')) {
            sortQuery[sortBy.substring(1)] = -1;
        } else {
            sortQuery[sortBy] = 1;
        }

        const projects = await Project.find(query).sort(sortQuery).skip(skip).limit(limit);

        // Add stage progress to each project
        const projectsWithProgress = await Promise.all(projects.map(async (project) => {
            const stages = await ProjectStage.find({ project_id: project._id }).sort({ stage_order: 1 });

            const totalStages = stages.length;
            const completedStages = stages.filter(s => s.status === 'Completed').length;
            const progress = totalStages > 0 ? Math.round((completedStages / totalStages) * 100) : 0;

            // Find current stage (first one that is In Progress or Pending)
            const currentStage = stages.find(s => s.status === 'In Progress') ||
                stages.find(s => s.status === 'Pending') ||
                (stages.length > 0 ? stages[stages.length - 1] : null);

            return {
                ...project.toObject(),
                progress,
                total_stages: totalStages,
                completed_stages: completedStages,
                current_stage_name: currentStage ? currentStage.stage_name : (project.status || 'Planning')
            };
        }));

        res.json({
            success: true,
            data: projectsWithProgress,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (err) {
        next(err);
    }
});

app.get('/api/projects/:id', authenticateToken, async (req, res, next) => {
    try {
        const project = await Project.findById(req.params.id);
        if (!project) {
            return res.status(404).json({ success: false, message: 'Project not found' });
        }
        // Normalize _id to id
        const projectObj = project.toObject();
        projectObj.id = projectObj._id.toString();
        delete projectObj._id;
        res.json({ success: true, data: projectObj });
    } catch (err) {
        next(err);
    }
});

app.post('/api/projects', authenticateToken, async (req, res, next) => {
    try {
        const { project_name, customer_name, site_address, area_sqft, status, customer_phone } = req.body;
        if (!project_name) {
            return res.status(400).json({ success: false, message: 'Project name is required' });
        }
        
        // Auto-set customer_phone if user is customer
        const finalCustomerPhone = customer_phone || (req.user.role === 'customer' ? req.user.phone : null);
        
        const newProject = new Project({
            project_name,
            customer_name,
            customer_phone: finalCustomerPhone,
            site_address,
            area_sqft,
            status: status || 'Planning',
            createdBy: req.user.id
        });
        await newProject.save();
        
        // Create default stages from StageMaster if project is created
        const defaultStages = await StageMaster.find().sort({ order: 1 });
        if (defaultStages.length > 0) {
            for (const stage of defaultStages) {
                await ProjectStage.create({
                    project_id: newProject._id,
                    stage_name: stage.name,
                    stage_order: stage.order,
                    status: 'Pending'
                });
            }
        }
        
        const projectObj = newProject.toObject();
        projectObj.id = projectObj._id.toString();
        delete projectObj._id;
        res.status(201).json({ success: true, data: projectObj });
    } catch (err) {
        next(err);
    }
});

app.put('/api/projects/:id', authenticateToken, async (req, res, next) => {
    try {
        const project = await Project.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!project) {
            return res.status(404).json({ success: false, message: 'Project not found' });
        }
        res.json(project);
    } catch (err) {
        next(err);
    }
});

// Get project materials
app.get('/api/projects/:id/materials', authenticateToken, async (req, res, next) => {
    try {
        const materials = await ProjectMaterial.find({ project_id: req.params.id }).populate('material_id', 'name unit price_per_unit');
        res.json(materials);
    } catch (err) {
        next(err);
    }
});

// Add material to project
app.post('/api/projects/:id/materials', authenticateToken, async (req, res, next) => {
    try {
        const { material_id, quantity, unit_price } = req.body;
        if (!material_id || !quantity || !unit_price) {
            return res.status(400).json({ success: false, message: 'Material ID, quantity and unit price are required' });
        }
        const project_id = req.params.id;
        const total_cost = quantity * unit_price;
        const newProjectMaterial = new ProjectMaterial({
            project_id,
            material_id,
            quantity,
            unit_price,
            total_cost
        });
        await newProjectMaterial.save();
        res.status(201).json(newProjectMaterial);
    } catch (err) {
        next(err);
    }
});

// Get project workers
app.get('/api/projects/:id/workers', authenticateToken, async (req, res, next) => {
    try {
        const workers = await ProjectWorker.find({ project_id: req.params.id }).populate('worker_id', 'name role daily_wage');
        res.json(workers);
    } catch (err) {
        next(err);
    }
});

// Add worker to project
app.post('/api/projects/:id/workers', authenticateToken, async (req, res, next) => {
    try {
        const { worker_id, days, daily_wage } = req.body;
        if (!worker_id || !days || !daily_wage) {
            return res.status(400).json({ success: false, message: 'Worker ID, days and daily wage are required' });
        }
        const project_id = req.params.id;
        const total_wage = days * daily_wage;
        const newProjectWorker = new ProjectWorker({
            project_id,
            worker_id,
            days,
            daily_wage,
            total_wage
        });
        await newProjectWorker.save();
        res.status(201).json(newProjectWorker);
    } catch (err) {
        next(err);
    }
});

// Get project costing
app.get('/api/projects/:id/costing', authenticateToken, async (req, res, next) => {
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
        next(err);
    }
});

// ==================== QUOTATION ROUTES ====================

app.get('/api/quotations', authenticateToken, async (req, res, next) => {
    try {
        const quotations = await Quotation.find().populate('project_id', 'project_name customer_name').sort({ createdAt: -1 });
        res.json(quotations);
    } catch (err) {
        next(err);
    }
});

app.get('/api/quotations/:id', authenticateToken, async (req, res, next) => {
    try {
        const quotation = await Quotation.findById(req.params.id).populate('project_id', 'project_name customer_name area_sqft');
        if (!quotation) {
            return res.status(404).json({ success: false, message: 'Quotation not found' });
        }

        const materials = await QuotationMaterial.find({ quotation_id: req.params.id }).populate('material_id', 'name unit');
        const workers = await QuotationWorker.find({ quotation_id: req.params.id }).populate('worker_id', 'name role');

        res.json({
            ...quotation.toObject(),
            materials,
            workers
        });
    } catch (err) {
        next(err);
    }
});

app.post('/api/quotation/generate', authenticateToken, async (req, res, next) => {
    try {
        const { project_id } = req.body;
        if (!project_id) {
            return res.status(400).json({ success: false, message: 'Project ID is required' });
        }

        // Get GST rate from AppSetting (default 18%)
        const gstSetting = await AppSetting.findOne({ key: 'gst_rate' });
        const gstRate = gstSetting ? (gstSetting.value / 100) : 0.18;

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
        const gst_amount = total_cost * gstRate;
        const grand_total = total_cost + gst_amount;

        const quotation_number = 'QTN-' + Date.now().toString().slice(-8);

        // Get the GST rate value to store with quotation
        const gstRateValue = gstSetting ? gstSetting.value : 18;
        
        const newQuotation = new Quotation({
            project_id,
            quotation_number,
            material_cost,
            labor_cost,
            total_cost,
            gst_rate: gstRateValue,
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
        next(err);
    }
});

// Delete project
app.delete('/api/projects/:id', authenticateToken, requireAdmin, async (req, res, next) => {
    try {
        await Project.findByIdAndDelete(req.params.id);
        // Also delete related project materials and workers
        await ProjectMaterial.deleteMany({ project_id: req.params.id });
        await ProjectWorker.deleteMany({ project_id: req.params.id });
        res.status(204).send();
    } catch (err) {
        next(err);
    }
});

// Delete project material
app.delete('/api/projects/:projectId/materials/:materialId', authenticateToken, async (req, res, next) => {
    try {
        await ProjectMaterial.findByIdAndDelete(req.params.materialId);
        res.status(204).send();
    } catch (err) {
        next(err);
    }
});

// Delete project worker
app.delete('/api/projects/:projectId/workers/:workerId', authenticateToken, async (req, res, next) => {
    try {
        await ProjectWorker.findByIdAndDelete(req.params.workerId);
        res.status(204).send();
    } catch (err) {
        next(err);
    }
});

// Delete quotation
app.delete('/api/quotations/:id', authenticateToken, requireAdmin, async (req, res, next) => {
    try {
        await Quotation.findByIdAndDelete(req.params.id);
        // Also delete related quotation materials and workers
        await QuotationMaterial.deleteMany({ quotation_id: req.params.id });
        await QuotationWorker.deleteMany({ quotation_id: req.params.id });
        res.status(204).send();
    } catch (err) {
        next(err);
    }
});

// ==================== SEED DATA ROUTE (for initial setup) ====================

app.post('/api/seed', async (req, res, next) => {
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

        // Create Users (passwords hashed with bcrypt)
        const hash = (p) => bcrypt.hashSync(p, 10);
        const admin = await User.create({ name: 'Admin', phone: '1234567890', password: hash('admin123'), role: 'admin' });
        const staff = await User.create({ name: 'Rahul Sharma', phone: '9876543210', password: hash('staff123'), role: 'staff' });
        const customer = await User.create({ name: 'Amit Patel', phone: '9988776655', password: hash('user123'), role: 'customer' });
        await User.create({ name: 'Suresh Kumar', phone: '9977665544', password: hash('user123'), role: 'customer' });

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
        next(err);
    }
});

// ==================== NEW ADVANCED FEATURES ROUTES ====================

// Stage Master Routes
app.get('/api/stages', authenticateToken, async (req, res, next) => {
    try {
        const stages = await StageMaster.find().sort({ order: 1 });
        res.json(stages);
    } catch (err) {
        next(err);
    }
});

app.post('/api/stages', authenticateToken, requireAdmin, async (req, res, next) => {
    try {
        const stage = new StageMaster(req.body);
        await stage.save();
        res.status(201).json(stage);
    } catch (err) {
        next(err);
    }
});

app.put('/api/stages/:id', authenticateToken, requireAdmin, async (req, res, next) => {
    try {
        const stage = await StageMaster.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(stage);
    } catch (err) {
        next(err);
    }
});

app.delete('/api/stages/:id', authenticateToken, requireAdmin, async (req, res, next) => {
    try {
        await StageMaster.findByIdAndDelete(req.params.id);
        res.json({ message: 'Stage deleted successfully' });
    } catch (err) {
        next(err);
    }
});

// Project Stage Routes
app.get('/api/projects/:id/stages', authenticateToken, async (req, res, next) => {
    try {
        const projectStages = await ProjectStage.find({ project_id: req.params.id })
            .sort({ stage_order: 1 });
        res.json(projectStages);
    } catch (err) {
        next(err);
    }
});

app.post('/api/projects/:id/stages', authenticateToken, async (req, res, next) => {
    try {
        const projectStage = new ProjectStage({
            project_id: req.params.id,
            ...req.body
        });
        await projectStage.save();
        res.status(201).json(projectStage);
    } catch (err) {
        next(err);
    }
});

app.put('/api/projects/:projectId/stages/:stageId', authenticateToken, async (req, res, next) => {
    try {
        const projectStage = await ProjectStage.findByIdAndUpdate(
            req.params.stageId,
            req.body,
            { new: true }
        );
        res.json(projectStage);
    } catch (err) {
        next(err);
    }
});

// Daily Entry Routes
app.get('/api/projects/:id/daily-entries', authenticateToken, async (req, res, next) => {
    try {
        const dailyEntries = await DailyEntry.find({ project_id: req.params.id })
            .populate('workers_present', 'name role')
            .sort({ date: -1 });
        res.json(dailyEntries);
    } catch (err) {
        next(err);
    }
});

app.post('/api/projects/:id/daily-entries', authenticateToken, async (req, res, next) => {
    try {
        const { workers_present, materials_used, extra_expenses, expense_description, notes, date } = req.body;
        
        const dailyEntry = new DailyEntry({
            project_id: req.params.id,
            date: date ? new Date(date) : new Date(),
            workers_present: workers_present || [],
            materials_used: materials_used || [],
            extra_expenses: extra_expenses || 0,
            expense_description,
            notes
        });

        // Calculate total daily cost: materials + extra expenses + worker wages
        let totalCost = dailyEntry.extra_expenses || 0;

        // Add material costs
        for (const material of dailyEntry.materials_used) {
            totalCost += material.cost || 0;
        }

        // Add worker wages (daily_wage × number of workers present)
        if (dailyEntry.workers_present && dailyEntry.workers_present.length > 0) {
            const workers = await Worker.find({ _id: { $in: dailyEntry.workers_present } });
            for (const worker of workers) {
                totalCost += worker.daily_wage || 0;
            }
        }

        dailyEntry.total_daily_cost = totalCost;
        await dailyEntry.save();

        res.status(201).json(dailyEntry);
    } catch (err) {
        next(err);
    }
});

app.delete('/api/daily-entries/:id', authenticateToken, requireAdmin, async (req, res, next) => {
    try {
        await DailyEntry.findByIdAndDelete(req.params.id);
        res.json({ message: 'Daily entry deleted successfully' });
    } catch (err) {
        next(err);
    }
});

// Payment Routes
app.get('/api/projects/:id/payments', authenticateToken, async (req, res, next) => {
    try {
        const payments = await Payment.find({ project_id: req.params.id })
            .sort({ due_date: 1 });
        res.json(payments);
    } catch (err) {
        next(err);
    }
});

app.post('/api/projects/:id/payments', authenticateToken, requireAdmin, async (req, res, next) => {
    try {
        const payment = new Payment({
            project_id: req.params.id,
            ...req.body
        });
        await payment.save();
        res.status(201).json(payment);
    } catch (err) {
        next(err);
    }
});

app.put('/api/payments/:id', authenticateToken, requireAdmin, async (req, res, next) => {
    try {
        const { paid_amount, payment_date, payment_mode, transaction_id, status } = req.body;
        const payment = await Payment.findById(req.params.id);
        if (!payment) {
            return res.status(404).json({ success: false, message: 'Payment not found' });
        }

        // Update payment
        if (paid_amount != null) payment.paid_amount = paid_amount;
        if (payment_date) payment.payment_date = new Date(payment_date);
        if (payment_mode) payment.payment_mode = payment_mode;
        if (transaction_id) payment.transaction_id = transaction_id;
        if (status) payment.status = status;

        // Auto-update status based on paid_amount
        if (paid_amount != null) {
            if (paid_amount >= payment.amount) {
                payment.status = 'Paid';
            } else if (paid_amount > 0) {
                payment.status = 'Partial';
            } else {
                payment.status = 'Pending';
            }
        }

        await payment.save();

        // Update project paid_amount
        const project = await Project.findById(payment.project_id);
        if (project) {
            const payments = await Payment.find({ project_id: payment.project_id });
            const totalPaid = payments.reduce((sum, p) => sum + (p.paid_amount || 0), 0);
            project.paid_amount = totalPaid;
            await project.save();
        }

        res.json(payment);
    } catch (err) {
        next(err);
    }
});

app.delete('/api/payments/:id', authenticateToken, requireAdmin, async (req, res, next) => {
    try {
        const payment = await Payment.findByIdAndDelete(req.params.id);
        if (!payment) {
            return res.status(404).json({ success: false, message: 'Payment not found' });
        }
        
        // Recalculate project paid_amount after deletion
        const project = await Project.findById(payment.project_id);
        if (project) {
            const payments = await Payment.find({ project_id: payment.project_id });
            const totalPaid = payments.reduce((sum, p) => sum + (p.paid_amount || 0), 0);
            project.paid_amount = totalPaid;
            await project.save();
        }
        
        res.status(204).send();
    } catch (err) {
        next(err);
    }
});

// Document Routes
app.get('/api/projects/:id/documents', authenticateToken, async (req, res, next) => {
    try {
        const documents = await Document.find({ project_id: req.params.id })
            .sort({ createdAt: -1 });
        res.json(documents);
    } catch (err) {
        next(err);
    }
});

app.post('/api/projects/:id/documents', authenticateToken, async (req, res, next) => {
    try {
        const document = new Document({
            project_id: req.params.id,
            ...req.body
        });
        await document.save();
        res.status(201).json(document);
    } catch (err) {
        next(err);
    }
});

app.delete('/api/documents/:id', authenticateToken, requireAdmin, async (req, res, next) => {
    try {
        const doc = await Document.findByIdAndDelete(req.params.id);
        if (!doc) {
            return res.status(404).json({ success: false, message: 'Document not found' });
        }
        res.status(204).send();
    } catch (err) {
        next(err);
    }
});

// ==================== WORKERS API ====================

// Get all workers (with pagination support)
app.get('/api/workers', authenticateToken, async (req, res, next) => {
    try {
        const page = parseInt(req.query.page || '1', 10);
        const limit = parseInt(req.query.limit || '50', 10);
        const skip = (page - 1) * limit;
        const sortBy = req.query.sort || '-createdAt';

        let sortQuery = {};
        if (sortBy.startsWith('-')) {
            sortQuery[sortBy.substring(1)] = -1;
        } else {
            sortQuery[sortBy] = 1;
        }

        const total = await Worker.countDocuments();
        const workers = await Worker.find().sort(sortQuery).skip(skip).limit(limit);

        // Return paginated response if page/limit specified, else direct array for backward compatibility
        if (req.query.page || req.query.limit) {
            res.json({
                success: true,
                data: workers,
                pagination: {
                    page,
                    limit,
                    total,
                    pages: Math.ceil(total / limit)
                }
            });
        } else {
            res.json(workers);
        }
    } catch (err) {
        next(err);
    }
});

// Get worker by ID
app.get('/api/workers/:id', authenticateToken, async (req, res, next) => {
    try {
        const worker = await Worker.findById(req.params.id);
        if (!worker) {
            return res.status(404).json({ success: false, message: 'Worker not found' });
        }
        const workerObj = worker.toObject();
        workerObj.id = workerObj._id.toString();
        delete workerObj._id;
        res.json({ success: true, data: workerObj });
    } catch (err) {
        next(err);
    }
});

// Create worker
app.post('/api/workers', authenticateToken, async (req, res, next) => {
    try {
        const { name, role, daily_wage, phone_number, location } = req.body;
        if (!name || daily_wage == null) {
            return res.status(400).json({ success: false, message: 'Name and daily wage are required' });
        }
        if (daily_wage < 0) {
            return res.status(400).json({ success: false, message: 'Daily wage must be positive' });
        }
        const worker = new Worker({ name, role: role || 'Worker', daily_wage, phone_number, location });
        await worker.save();
        const workerObj = worker.toObject();
        workerObj.id = workerObj._id.toString();
        delete workerObj._id;
        res.status(201).json({ success: true, data: workerObj });
    } catch (err) {
        next(err);
    }
});

// Update worker
app.put('/api/workers/:id', authenticateToken, async (req, res, next) => {
    try {
        const worker = await Worker.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true, runValidators: true }
        );
        if (!worker) {
            return res.status(404).json({ error: 'Worker not found' });
        }
        res.json(worker);
    } catch (err) {
        next(err);
    }
});

// Delete worker
app.delete('/api/workers/:id', authenticateToken, requireAdmin, async (req, res, next) => {
    try {
        const worker = await Worker.findByIdAndDelete(req.params.id);
        if (!worker) {
            return res.status(404).json({ success: false, message: 'Worker not found' });
        }
        res.status(204).send();
    } catch (err) {
        next(err);
    }
});

// ==================== MATERIALS API ====================

// Get all materials (with pagination support)
app.get('/api/materials', authenticateToken, async (req, res, next) => {
    try {
        const page = parseInt(req.query.page || '1', 10);
        const limit = parseInt(req.query.limit || '50', 10);
        const skip = (page - 1) * limit;
        const sortBy = req.query.sort || '-createdAt';
        const categoryFilter = req.query.category_id;

        let query = {};
        if (categoryFilter) {
            query.category_id = categoryFilter;
        }

        let sortQuery = {};
        if (sortBy.startsWith('-')) {
            sortQuery[sortBy.substring(1)] = -1;
        } else {
            sortQuery[sortBy] = 1;
        }

        const total = await Material.countDocuments(query);
        const materials = await Material.find(query)
            .populate('category_id', 'name')
            .sort(sortQuery)
            .skip(skip)
            .limit(limit);

        // Transform to include category_name
        const materialsWithCategory = materials.map(m => {
            const obj = m.toObject();
            if (obj.category_id) {
                obj.category_name = obj.category_id.name;
            }
            return obj;
        });

        // Return paginated response if page/limit specified, else direct array for backward compatibility
        if (req.query.page || req.query.limit) {
            res.json({
                success: true,
                data: materialsWithCategory,
                pagination: {
                    page,
                    limit,
                    total,
                    pages: Math.ceil(total / limit)
                }
            });
        } else {
            res.json(materialsWithCategory);
        }
    } catch (err) {
        next(err);
    }
});

// Get material by ID
app.get('/api/materials/:id', authenticateToken, async (req, res, next) => {
    try {
        const material = await Material.findById(req.params.id).populate('category_id', 'name');
        if (!material) {
            return res.status(404).json({ success: false, message: 'Material not found' });
        }
        const materialObj = material.toObject();
        materialObj.id = materialObj._id.toString();
        delete materialObj._id;
        if (materialObj.category_id) {
            materialObj.category_name = materialObj.category_id.name;
        }
        res.json({ success: true, data: materialObj });
    } catch (err) {
        next(err);
    }
});

// Create material
app.post('/api/materials', authenticateToken, async (req, res, next) => {
    try {
        const { name, category_id, price_per_unit, unit } = req.body;
        if (!name || !price_per_unit) {
            return res.status(400).json({ success: false, message: 'Name and price per unit are required' });
        }
        if (price_per_unit < 0) {
            return res.status(400).json({ success: false, message: 'Price must be positive' });
        }
        const material = new Material({ name, category_id, price_per_unit, unit: unit || 'unit' });
        await material.save();
        res.status(201).json(material);
    } catch (err) {
        next(err);
    }
});

// Update material
app.put('/api/materials/:id', authenticateToken, async (req, res, next) => {
    try {
        const material = await Material.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true, runValidators: true }
        );
        if (!material) {
            return res.status(404).json({ error: 'Material not found' });
        }
        res.json(material);
    } catch (err) {
        next(err);
    }
});

// Delete material
app.delete('/api/materials/:id', authenticateToken, requireAdmin, async (req, res, next) => {
    try {
        const material = await Material.findByIdAndDelete(req.params.id);
        if (!material) {
            return res.status(404).json({ success: false, message: 'Material not found' });
        }
        res.status(204).send();
    } catch (err) {
        next(err);
    }
});

// Get all material categories
app.get('/api/material-categories', authenticateToken, async (req, res, next) => {
    try {
        const categories = await MaterialCategory.find();
        res.json(categories);
    } catch (err) {
        next(err);
    }
});

// Health check
app.get('/api/health', async (req, res) => {
    try {
        // Check MongoDB connection
        const dbState = mongoose.connection.readyState;
        const isConnected = dbState === 1; // 1 = connected
        
        if (isConnected) {
            res.status(200).json({
                success: true,
                status: 'ok',
                database: 'connected',
                timestamp: new Date().toISOString()
            });
        } else {
            res.status(503).json({
                success: false,
                status: 'unhealthy',
                database: 'disconnected',
                timestamp: new Date().toISOString()
            });
        }
    } catch (err) {
        res.status(503).json({
            success: false,
            status: 'error',
            message: err.message,
            timestamp: new Date().toISOString()
        });
    }
});

// ==================== ANALYTICS ENDPOINTS ====================

// Get analytics overview
app.get('/api/analytics/overview', authenticateToken, async (req, res, next) => {
    try {
        const projects = await Project.find();
        const materials = await Material.find();
        const workers = await Worker.find();
        const payments = await Payment.find({ status: 'Paid' });
        
        // Calculate financial stats
        const totalRevenue = projects.reduce((sum, p) => sum + (p.paid_amount || 0), 0);
        const totalCost = projects.reduce((sum, p) => sum + (p.total_cost || 0), 0);
        const profit = totalRevenue - totalCost;
        const profitMargin = totalCost > 0 ? ((profit / totalCost) * 100).toFixed(2) : 0;
        
        // Monthly revenue (last 6 months)
        const monthlyRevenue = [];
        const now = new Date();
        for (let i = 5; i >= 0; i--) {
            const date = new Date(now.getFullYear(), now.getMonth() - i, 1);
            const monthStart = new Date(date.getFullYear(), date.getMonth(), 1);
            const monthEnd = new Date(date.getFullYear(), date.getMonth() + 1, 0, 23, 59, 59);
            
            const monthPayments = await Payment.find({
                payment_date: { $gte: monthStart, $lte: monthEnd },
                status: 'Paid'
            });
            const revenue = monthPayments.reduce((sum, p) => sum + (p.paid_amount || 0), 0);
            monthlyRevenue.push({
                month: date.toLocaleString('default', { month: 'short', year: 'numeric' }),
                revenue: Math.round(revenue),
                monthIndex: date.getMonth()
            });
        }
        
        // Project status distribution
        const statusCount = {
            'Planning': projects.filter(p => p.status === 'Planning').length,
            'In Progress': projects.filter(p => p.status === 'In Progress').length,
            'Completed': projects.filter(p => p.status === 'Completed').length,
            'Pending': projects.filter(p => p.status === 'Pending').length,
        };
        
        // Outstanding payments
        const outstandingPayments = await Payment.find({ status: { $in: ['Pending', 'Partial'] } });
        const totalOutstanding = outstandingPayments.reduce((sum, p) => {
            return sum + ((p.amount || 0) - (p.paid_amount || 0));
        }, 0);
        
        // Cost breakdown
        const materialCost = projects.reduce((sum, p) => {
            return sum + (p.total_cost || 0) * 0.6; // Estimate 60% materials
        }, 0);
        const laborCost = projects.reduce((sum, p) => {
            return sum + (p.total_cost || 0) * 0.4; // Estimate 40% labor
        }, 0);
        
        res.json({
            success: true,
            data: {
                financial: {
                    totalRevenue: Math.round(totalRevenue),
                    totalCost: Math.round(totalCost),
                    profit: Math.round(profit),
                    profitMargin: parseFloat(profitMargin),
                    totalOutstanding: Math.round(totalOutstanding),
                },
                projects: {
                    total: projects.length,
                    active: projects.filter(p => p.status === 'In Progress').length,
                    completed: projects.filter(p => p.status === 'Completed').length,
                    planning: projects.filter(p => p.status === 'Planning').length,
                    statusDistribution: statusCount,
                },
                resources: {
                    totalMaterials: materials.length,
                    totalWorkers: workers.length,
                },
                costs: {
                    materialCost: Math.round(materialCost),
                    laborCost: Math.round(laborCost),
                },
                monthlyRevenue,
            }
        });
    } catch (err) {
        next(err);
    }
});

// ==================== NOTIFICATION ENDPOINTS ====================

// Get user notifications
app.get('/api/notifications', authenticateToken, async (req, res, next) => {
    try {
        const { read, limit = 50 } = req.query;
        let query = { user_id: req.user.userId || req.user.id };
        if (read !== undefined) {
            query.read = read === 'true';
        }
        
        const notifications = await Notification.find(query)
            .sort({ createdAt: -1 })
            .limit(parseInt(limit));
        
        const normalized = notifications.map(n => {
            const obj = n.toObject();
            obj.id = obj._id.toString();
            delete obj._id;
            return obj;
        });
        
        const unreadCount = await Notification.countDocuments({ user_id: req.user.userId || req.user.id, read: false });
        
        res.json({
            success: true,
            data: normalized,
            unreadCount
        });
    } catch (err) {
        next(err);
    }
});

// Mark notification as read
app.put('/api/notifications/:id/read', authenticateToken, async (req, res, next) => {
    try {
        const notification = await Notification.findOne({
            _id: req.params.id,
            user_id: req.user.userId || req.user.id
        });
        
        if (!notification) {
            return res.status(404).json({ success: false, message: 'Notification not found' });
        }
        
        notification.read = true;
        await notification.save();
        
        res.json({ success: true });
    } catch (err) {
        next(err);
    }
});

// Mark all notifications as read
app.put('/api/notifications/read-all', authenticateToken, async (req, res, next) => {
    try {
        await Notification.updateMany(
            { user_id: req.user.userId || req.user.id, read: false },
            { read: true }
        );
        res.json({ success: true });
    } catch (err) {
        next(err);
    }
});

// ==================== GLOBAL SEARCH ENDPOINT ====================

app.get('/api/search', authenticateToken, async (req, res, next) => {
    try {
        const { q } = req.query;
        if (!q || q.length < 2) {
            return res.json({
                success: true,
                data: { projects: [], materials: [], workers: [] }
            });
        }
        
        const searchRegex = new RegExp(q, 'i');
        
        // Search projects
        const projects = await Project.find({
            $or: [
                { project_name: searchRegex },
                { customer_name: searchRegex },
                { customer_phone: searchRegex },
                { site_address: searchRegex },
            ]
        }).limit(10).select('project_name customer_name status customer_phone');
        
        // Search materials
        const materials = await Material.find({
            name: searchRegex
        }).limit(10).select('name price_per_unit unit category_id').populate('category_id', 'name');
        
        // Search workers
        const workers = await Worker.find({
            $or: [
                { name: searchRegex },
                { phone_number: searchRegex },
                { role: searchRegex },
            ]
        }).limit(10).select('name role daily_wage phone_number');
        
        const normalizeArray = (arr) => arr.map(item => {
            const obj = item.toObject();
            obj.id = obj._id.toString();
            delete obj._id;
            return obj;
        });
        
        res.json({
            success: true,
            data: {
                projects: normalizeArray(projects),
                materials: normalizeArray(materials),
                workers: normalizeArray(workers),
            }
        });
    } catch (err) {
        next(err);
    }
});

// ==================== ENHANCED DOCUMENT UPLOAD ====================

// Upload document (multipart) - Serverless compatible (memory storage)
app.post('/api/documents/upload', authenticateToken, documentUpload.single('file'), async (req, res, next) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'No file uploaded' });
        }
        
        const { project_id, document_type, description } = req.body;
        
        if (!project_id) {
            return res.status(400).json({ success: false, message: 'Project ID is required' });
        }
        
        // Convert file to base64 for serverless storage (like profile photos)
        const base64File = req.file.buffer.toString('base64');
        const fileDataUri = `data:${req.file.mimetype};base64,${base64File}`;
        
        const document = new Document({
            project_id: project_id,
            document_type: document_type || 'Other',
            file_url: fileDataUri, // Store as base64 data URI (serverless compatible)
            file_name: req.file.originalname,
            file_size: req.file.size,
            description: description,
            uploaded_by: req.user.userId || req.user.id,
        });
        
        await document.save();
        
        const docObj = document.toObject();
        docObj.id = docObj._id.toString();
        delete docObj._id;
        
        res.json({ success: true, data: docObj });
    } catch (err) {
        next(err);
    }
});

// ==================== SCHEDULED TASKS (CRON JOBS) ====================

// Check for due payments daily at 9 AM
cron.schedule('0 9 * * *', async () => {
    try {
        const tomorrow = new Date();
        tomorrow.setDate(tomorrow.getDate() + 1);
        tomorrow.setHours(0, 0, 0, 0);
        
        const dayAfter = new Date(tomorrow);
        dayAfter.setDate(dayAfter.getDate() + 1);
        
        // Find payments due tomorrow
        const duePayments = await Payment.find({
            due_date: { $gte: tomorrow, $lt: dayAfter },
            status: { $ne: 'Paid' }
        }).populate('project_id');
        
        // Create notifications
        for (const payment of duePayments) {
            if (payment.project_id && payment.project_id.createdBy) {
                await Notification.create({
                    user_id: payment.project_id.createdBy,
                    type: 'payment_reminder',
                    title: 'Payment Due Tomorrow',
                    message: `Payment of ₹${payment.amount} is due tomorrow for project ${payment.project_id.project_name}`,
                    related_id: payment._id,
                    related_type: 'payment',
                    read: false
                });
            }
        }
        
        logger.info(`Created ${duePayments.length} payment reminders`);
    } catch (err) {
        logger.error('Payment reminder cron error:', err);
    }
});

// Check for overdue payments daily at 9 AM
cron.schedule('0 9 * * *', async () => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        // Find overdue payments
        const overduePayments = await Payment.find({
            due_date: { $lt: today },
            status: { $ne: 'Paid' }
        }).populate('project_id');
        
        // Update status and create notifications
        for (const payment of overduePayments) {
            if (payment.status !== 'Overdue') {
                payment.status = 'Overdue';
                await payment.save();
            }
            
            if (payment.project_id && payment.project_id.createdBy) {
                await Notification.create({
                    user_id: payment.project_id.createdBy,
                    type: 'payment_reminder',
                    title: 'Overdue Payment',
                    message: `Payment of ₹${payment.amount} is overdue for project ${payment.project_id.project_name}`,
                    related_id: payment._id,
                    related_type: 'payment',
                    read: false
                });
            }
        }
        
        logger.info(`Processed ${overduePayments.length} overdue payments`);
    } catch (err) {
        logger.error('Overdue payment cron error:', err);
    }
});

// Central error handler (must be last)
app.use(errorHandler);

app.listen(config.port, () => {
    logger.info(`Server running on port ${config.port}`, { env: config.nodeEnv });
    logger.info('Scheduled tasks initialized');
});
