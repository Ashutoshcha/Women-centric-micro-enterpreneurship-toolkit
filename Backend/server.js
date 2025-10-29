// server.js - SheRise Toolkit Backend
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/sherise-toolkit', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => console.log('Connected to MongoDB'));

// ==================== SCHEMAS ====================

// User Schema (Entrepreneur, Mentor, Volunteer)
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { 
    type: String, 
    enum: ['Entrepreneur', 'Mentor', 'Volunteer'], 
    required: true 
  },
  bio: String,
  phone: String,
  location: String,
  businessType: String, // For entrepreneurs
  expertise: [String], // For mentors
  isVerified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date
});

// Contact/Join Form Submissions
const contactSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  role: { type: String, required: true },
  message: String,
  status: { type: String, enum: ['new', 'contacted', 'resolved'], default: 'new' },
  submittedAt: { type: Date, default: Date.now }
});

// Success Stories
const storySchema = new mongoose.Schema({
  name: { type: String, required: true },
  title: { type: String, required: true },
  description: { type: String, required: true },
  businessType: String,
  imageUrl: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  isPublished: { type: Boolean, default: false },
  likes: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

// Product Cards (Shop Builder)
const productSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  productName: { type: String, required: true },
  price: { type: String, required: true },
  description: String,
  category: String,
  imageUrl: String,
  isActive: { type: Boolean, default: true },
  views: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Finance Calculations History
const financeCalculationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  costPrice: { type: Number, required: true },
  sellingPrice: { type: Number, required: true },
  quantity: { type: Number, required: true },
  profitPerItem: { type: Number, required: true },
  monthlyProfit: { type: Number, required: true },
  calculatedAt: { type: Date, default: Date.now }
});

// Training Resources
const resourceSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  category: { 
    type: String, 
    enum: ['Business Basics', 'Finance', 'Marketing', 'Legal', 'Operations', 'Growth'],
    required: true 
  },
  type: { type: String, enum: ['pdf', 'video', 'guide', 'template'], required: true },
  url: String,
  fileUrl: String,
  downloadCount: { type: Number, default: 0 },
  isPublished: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

// Mentorship Connections
const mentorshipSchema = new mongoose.Schema({
  mentorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  entrepreneurId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { 
    type: String, 
    enum: ['requested', 'accepted', 'active', 'completed', 'declined'],
    default: 'requested'
  },
  topics: [String],
  notes: String,
  sessionCount: { type: Number, default: 0 },
  startDate: Date,
  endDate: Date,
  createdAt: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Contact = mongoose.model('Contact', contactSchema);
const Story = mongoose.model('Story', storySchema);
const Product = mongoose.model('Product', productSchema);
const FinanceCalculation = mongoose.model('FinanceCalculation', financeCalculationSchema);
const Resource = mongoose.model('Resource', resourceSchema);
const Mentorship = mongoose.model('Mentorship', mentorshipSchema);

// ==================== MIDDLEWARE ====================

// Authentication Middleware
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'sherise-secret-key');
    req.userId = decoded.userId;
    req.userRole = decoded.role;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Role-based access control
const roleCheck = (...allowedRoles) => {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.userRole)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    next();
  };
};

// ==================== AUTH ROUTES ====================

// Register new user
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role, bio, phone, location, businessType, expertise } = req.body;

    // Validation
    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: 'Name, email, password, and role are required' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
      role,
      bio,
      phone,
      location,
      businessType,
      expertise: expertise || []
    });

    await user.save();

    // Generate token
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET || 'sherise-secret-key',
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'Registration successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed', details: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET || 'sherise-secret-key',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        bio: user.bio
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user profile
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update user profile
app.put('/api/auth/profile', authMiddleware, async (req, res) => {
  try {
    const { name, bio, phone, location, businessType, expertise } = req.body;
    
    const updateData = {};
    if (name) updateData.name = name;
    if (bio !== undefined) updateData.bio = bio;
    if (phone) updateData.phone = phone;
    if (location) updateData.location = location;
    if (businessType) updateData.businessType = businessType;
    if (expertise) updateData.expertise = expertise;

    const user = await User.findByIdAndUpdate(
      req.userId,
      updateData,
      { new: true }
    ).select('-password');

    res.json({ message: 'Profile updated', user });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// ==================== CONTACT/JOIN ROUTES ====================

// Submit contact/join form
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, role, message } = req.body;

    if (!name || !email || !role) {
      return res.status(400).json({ error: 'Name, email, and role are required' });
    }

    const contact = new Contact({
      name,
      email: email.toLowerCase(),
      role,
      message
    });

    await contact.save();

    res.status(201).json({
      message: `Thank you, ${name}! Your registration as ${role} has been received.`,
      contact: {
        id: contact._id,
        name: contact.name,
        role: contact.role
      }
    });
  } catch (error) {
    console.error('Contact form error:', error);
    res.status(500).json({ error: 'Failed to submit form' });
  }
});

// Get all contact submissions (admin only)
app.get('/api/contact', authMiddleware, async (req, res) => {
  try {
    const { status, role } = req.query;
    const filter = {};
    if (status) filter.status = status;
    if (role) filter.role = role;

    const contacts = await Contact.find(filter).sort({ submittedAt: -1 });
    res.json(contacts);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch contacts' });
  }
});

// ==================== SUCCESS STORIES ROUTES ====================

// Get all published stories
app.get('/api/stories', async (req, res) => {
  try {
    const stories = await Story.find({ isPublished: true })
      .sort({ createdAt: -1 })
      .select('-__v');
    res.json(stories);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch stories' });
  }
});

// Get single story
app.get('/api/stories/:id', async (req, res) => {
  try {
    const story = await Story.findById(req.params.id);
    if (!story) {
      return res.status(404).json({ error: 'Story not found' });
    }
    res.json(story);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch story' });
  }
});

// Create story (authenticated users)
app.post('/api/stories', authMiddleware, async (req, res) => {
  try {
    const { name, title, description, businessType, imageUrl } = req.body;

    if (!name || !title || !description) {
      return res.status(400).json({ error: 'Name, title, and description are required' });
    }

    const story = new Story({
      name,
      title,
      description,
      businessType,
      imageUrl,
      userId: req.userId,
      isPublished: req.userRole === 'Mentor' || req.userRole === 'Volunteer'
    });

    await story.save();
    res.status(201).json({ message: 'Story created', story });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create story' });
  }
});

// Like a story
app.post('/api/stories/:id/like', async (req, res) => {
  try {
    const story = await Story.findByIdAndUpdate(
      req.params.id,
      { $inc: { likes: 1 } },
      { new: true }
    );
    if (!story) {
      return res.status(404).json({ error: 'Story not found' });
    }
    res.json({ message: 'Story liked', likes: story.likes });
  } catch (error) {
    res.status(500).json({ error: 'Failed to like story' });
  }
});

// ==================== PRODUCT/SHOP BUILDER ROUTES ====================

// Get user's products
app.get('/api/products', authMiddleware, async (req, res) => {
  try {
    const products = await Product.find({ userId: req.userId })
      .sort({ createdAt: -1 });
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// Get all active products (public)
app.get('/api/products/public', async (req, res) => {
  try {
    const { category, search } = req.query;
    const filter = { isActive: true };
    
    if (category) filter.category = category;
    if (search) {
      filter.$or = [
        { productName: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    const products = await Product.find(filter)
      .populate('userId', 'name location')
      .sort({ createdAt: -1 });
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { $inc: { views: 1 } },
      { new: true }
    ).populate('userId', 'name email location');
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json(product);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch product' });
  }
});

// Create product
app.post('/api/products', authMiddleware, roleCheck('Entrepreneur'), async (req, res) => {
  try {
    const { productName, price, description, category, imageUrl } = req.body;

    if (!productName || !price) {
      return res.status(400).json({ error: 'Product name and price are required' });
    }

    const product = new Product({
      userId: req.userId,
      productName,
      price,
      description,
      category,
      imageUrl
    });

    await product.save();
    res.status(201).json({ message: 'Product created', product });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create product' });
  }
});

// Update product
app.put('/api/products/:id', authMiddleware, async (req, res) => {
  try {
    const { productName, price, description, category, imageUrl, isActive } = req.body;

    const product = await Product.findOne({ 
      _id: req.params.id, 
      userId: req.userId 
    });

    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    if (productName) product.productName = productName;
    if (price) product.price = price;
    if (description !== undefined) product.description = description;
    if (category) product.category = category;
    if (imageUrl !== undefined) product.imageUrl = imageUrl;
    if (isActive !== undefined) product.isActive = isActive;
    product.updatedAt = new Date();

    await product.save();
    res.json({ message: 'Product updated', product });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update product' });
  }
});

// Delete product
app.delete('/api/products/:id', authMiddleware, async (req, res) => {
  try {
    const product = await Product.findOneAndDelete({
      _id: req.params.id,
      userId: req.userId
    });

    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    res.json({ message: 'Product deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete product' });
  }
});

// ==================== FINANCE CALCULATOR ROUTES ====================

// Save calculation
app.post('/api/finance/calculate', authMiddleware, roleCheck('Entrepreneur'), async (req, res) => {
  try {
    const { costPrice, sellingPrice, quantity } = req.body;

    if (!costPrice || !sellingPrice || !quantity) {
      return res.status(400).json({ error: 'Cost price, selling price, and quantity are required' });
    }

    const profitPerItem = sellingPrice - costPrice;
    const monthlyProfit = profitPerItem * quantity;

    const calculation = new FinanceCalculation({
      userId: req.userId,
      costPrice,
      sellingPrice,
      quantity,
      profitPerItem,
      monthlyProfit
    });

    await calculation.save();

    res.json({
      message: 'Calculation saved',
      result: {
        profitPerItem,
        monthlyProfit,
        profitMargin: ((profitPerItem / sellingPrice) * 100).toFixed(2) + '%'
      },
      calculation
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to save calculation' });
  }
});

// Get calculation history
app.get('/api/finance/history', authMiddleware, async (req, res) => {
  try {
    const { limit = 20 } = req.query;
    const calculations = await FinanceCalculation.find({ userId: req.userId })
      .sort({ calculatedAt: -1 })
      .limit(parseInt(limit));
    res.json(calculations);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

// Get finance statistics
app.get('/api/finance/stats', authMiddleware, roleCheck('Entrepreneur'), async (req, res) => {
  try {
    const calculations = await FinanceCalculation.find({ userId: req.userId });
    
    if (calculations.length === 0) {
      return res.json({
        totalCalculations: 0,
        averageProfit: 0,
        totalProjectedProfit: 0
      });
    }

    const totalProjectedProfit = calculations.reduce((sum, calc) => sum + calc.monthlyProfit, 0);
    const averageProfit = totalProjectedProfit / calculations.length;

    res.json({
      totalCalculations: calculations.length,
      averageProfit: averageProfit.toFixed(2),
      totalProjectedProfit: totalProjectedProfit.toFixed(2),
      lastCalculation: calculations[0]
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ==================== RESOURCES ROUTES ====================

// Get all resources
app.get('/api/resources', async (req, res) => {
  try {
    const { category, type } = req.query;
    const filter = { isPublished: true };
    
    if (category) filter.category = category;
    if (type) filter.type = type;

    const resources = await Resource.find(filter).sort({ createdAt: -1 });
    res.json(resources);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch resources' });
  }
});

// Download resource (track count)
app.get('/api/resources/:id/download', async (req, res) => {
  try {
    const resource = await Resource.findByIdAndUpdate(
      req.params.id,
      { $inc: { downloadCount: 1 } },
      { new: true }
    );

    if (!resource) {
      return res.status(404).json({ error: 'Resource not found' });
    }

    res.json({
      message: 'Download tracked',
      resource: {
        title: resource.title,
        url: resource.url || resource.fileUrl,
        type: resource.type
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to track download' });
  }
});

// Create resource (admin/mentor/volunteer)
app.post('/api/resources', authMiddleware, roleCheck('Mentor', 'Volunteer'), async (req, res) => {
  try {
    const { title, description, category, type, url, fileUrl } = req.body;

    if (!title || !category || !type) {
      return res.status(400).json({ error: 'Title, category, and type are required' });
    }

    const resource = new Resource({
      title,
      description,
      category,
      type,
      url,
      fileUrl
    });

    await resource.save();
    res.status(201).json({ message: 'Resource created', resource });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create resource' });
  }
});

// ==================== MENTORSHIP ROUTES ====================

// Get available mentors
app.get('/api/mentors', async (req, res) => {
  try {
    const { expertise } = req.query;
    const filter = { role: 'Mentor', isVerified: true };
    
    if (expertise) {
      filter.expertise = { $in: [expertise] };
    }

    const mentors = await User.find(filter)
      .select('name bio location expertise')
      .limit(50);
    res.json(mentors);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch mentors' });
  }
});

// Request mentorship
app.post('/api/mentorship/request', authMiddleware, roleCheck('Entrepreneur'), async (req, res) => {
  try {
    const { mentorId, topics, notes } = req.body;

    if (!mentorId) {
      return res.status(400).json({ error: 'Mentor ID is required' });
    }

    // Check if mentor exists
    const mentor = await User.findOne({ _id: mentorId, role: 'Mentor' });
    if (!mentor) {
      return res.status(404).json({ error: 'Mentor not found' });
    }

    // Check for existing active mentorship
    const existing = await Mentorship.findOne({
      mentorId,
      entrepreneurId: req.userId,
      status: { $in: ['requested', 'accepted', 'active'] }
    });

    if (existing) {
      return res.status(400).json({ error: 'You already have an active mentorship request with this mentor' });
    }

    const mentorship = new Mentorship({
      mentorId,
      entrepreneurId: req.userId,
      topics: topics || [],
      notes
    });

    await mentorship.save();
    res.status(201).json({ message: 'Mentorship request sent', mentorship });
  } catch (error) {
    res.status(500).json({ error: 'Failed to request mentorship' });
  }
});

// Get mentorships (as mentor or entrepreneur)
app.get('/api/mentorship', authMiddleware, async (req, res) => {
  try {
    const { role, status } = req.query;
    let filter = {};

    if (req.userRole === 'Mentor') {
      filter.mentorId = req.userId;
    } else if (req.userRole === 'Entrepreneur') {
      filter.entrepreneurId = req.userId;
    }

    if (status) filter.status = status;

    const mentorships = await Mentorship.find(filter)
      .populate('mentorId', 'name email expertise')
      .populate('entrepreneurId', 'name email businessType')
      .sort({ createdAt: -1 });

    res.json(mentorships);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch mentorships' });
  }
});

// Update mentorship status
app.put('/api/mentorship/:id', authMiddleware, async (req, res) => {
  try {
    const { status, notes, sessionCount } = req.body;

    const mentorship = await Mentorship.findById(req.params.id);
    if (!mentorship) {
      return res.status(404).json({ error: 'Mentorship not found' });
    }

    // Check authorization
    if (mentorship.mentorId.toString() !== req.userId && 
        mentorship.entrepreneurId.toString() !== req.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    if (status) {
      mentorship.status = status;
      if (status === 'active' && !mentorship.startDate) {
        mentorship.startDate = new Date();
      }
      if (status === 'completed' && !mentorship.endDate) {
        mentorship.endDate = new Date();
      }
    }

    if (notes) mentorship.notes = notes;
    if (sessionCount !== undefined) mentorship.sessionCount = sessionCount;

    await mentorship.save();
    res.json({ message: 'Mentorship updated', mentorship });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update mentorship' });
  }
});

// ==================== DASHBOARD/ANALYTICS ROUTES ====================

// Get user dashboard
app.get('/api/dashboard', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const userRole = req.userRole;

    let dashboardData = {
      role: userRole,
      userName: '',
    };

    // Get user info
    const user = await User.findById(userId).select('name email');
    dashboardData.userName = user.name;

    if (userRole === 'Entrepreneur') {
      const [productCount, calculationCount, activeMentorships, latestProducts] = await Promise.all([
        Product.countDocuments({ userId }),
        FinanceCalculation.countDocuments({ userId }),
        Mentorship.countDocuments({ 
          entrepreneurId: userId, 
          status: { $in: ['active', 'accepted'] }
        }),
        Product.find({ userId }).sort({ createdAt: -1 }).limit(5)
      ]);

      dashboardData.products = productCount;
      dashboardData.calculations = calculationCount;
      dashboardData.mentorships = activeMentorships;
      dashboardData.latestProducts = latestProducts;

    } else if (userRole === 'Mentor') {
      const [activeMentees, totalSessions, pendingRequests] = await Promise.all([
        Mentorship.countDocuments({ mentorId: userId, status: 'active' }),
        Mentorship.aggregate([
          { $match: { mentorId: mongoose.Types.ObjectId(userId) } },
          { $group: { _id: null, total: { $sum: '$sessionCount' } } }
        ]),
        Mentorship.countDocuments({ mentorId: userId, status: 'requested' })
      ]);

      dashboardData.activeMentees = activeMentees;
      dashboardData.totalSessions = totalSessions[0]?.total || 0;
      dashboardData.pendingRequests = pendingRequests;
    }

    res.json(dashboardData);
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// Get platform statistics (public)
app.get('/api/stats/platform', async (req, res) => {
  try {
    const [totalUsers, totalEntrepreneurs, totalProducts, totalStories] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ role: 'Entrepreneur' }),
      Product.countDocuments({ isActive: true }),
      Story.countDocuments()
    ]);

    res.json({
      totalUsers,
      totalEntrepreneurs,
      totalProducts,
      totalStories
    });
  } catch (error) {
    console.error('Error fetching platform stats:', error);
    res.status(500).json({ message: 'Server Error' });
  }
});
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
