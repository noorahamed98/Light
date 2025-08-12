require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const AWS = require('aws-sdk');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');

const app = express();

// Enhanced CORS configuration
app.use(cors({
  origin: [
    "http://localhost:3000",
    "http://localhost:5000", 
    "http://127.0.0.1:5500",
    "http://127.0.0.1:3000",
    "*" // Remove this in production and specify exact origins
  ],
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

// Handle preflight requests
app.options('*', cors());

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));

// Serve static files from public directory
app.use(express.static('public'));

// Configure AWS (only if credentials are provided)
if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
  AWS.config.update({
    region: process.env.AWS_REGION || 'ap-south-1',
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  });
} else {
  console.log("⚠️  AWS credentials not provided. AWS IoT features will be disabled.");
}

// MongoDB Connection with better error handling
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/iot_management';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => {
  console.log("✅ MongoDB Connected to:", MONGODB_URI);
})
.catch((err) => {
  console.error("❌ MongoDB connection error:", err.message);
  console.log("💡 Make sure MongoDB is running and accessible");
});

// Schemas (keeping your existing schemas)
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
  createdAt: { type: Date, default: Date.now }
});

const projectSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  status: { type: String, enum: ['active', 'inactive'], default: 'active' }
});

const vendorSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  contactEmail: String,
  contactPhone: String,
  address: String,
  website: String,
  createdAt: { type: Date, default: Date.now }
});

const parameterSchema = new mongoose.Schema({
  name: { type: String, required: true },
  dataType: { type: String, enum: ['string', 'number', 'boolean', 'json'], required: true },
  unit: String,
  minValue: Number,
  maxValue: Number,
  description: String,
  createdAt: { type: Date, default: Date.now }
});

const itemTypeSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  parameters: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Parameter' }],
  vendor: { type: mongoose.Schema.Types.ObjectId, ref: 'Vendor' },
  createdAt: { type: Date, default: Date.now }
});

const messagingPolicySchema = new mongoose.Schema({
  name: { type: String, required: true },
  protocol: { type: String, enum: ['MQTT', 'HTTP', 'WebSocket'], required: true },
  topicStructure: String,
  qos: { type: Number, enum: [0, 1, 2], default: 1 },
  retainMessage: { type: Boolean, default: false },
  messageFormat: { type: String, enum: ['JSON', 'XML', 'Binary'], default: 'JSON' },
  createdAt: { type: Date, default: Date.now }
});

const communicationPolicySchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  messagingPolicies: [{ type: mongoose.Schema.Types.ObjectId, ref: 'MessagingPolicy' }],
  connectionTimeout: { type: Number, default: 30 },
  keepAlive: { type: Number, default: 60 },
  createdAt: { type: Date, default: Date.now }
});

const spaceTypeSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  coordinates: {
    latitude: Number,
    longitude: Number
  },
  area: Number,
  capacity: Number,
  createdAt: { type: Date, default: Date.now }
});

const deviceSchema = new mongoose.Schema({
  name: { type: String, required: true },
  deviceId: { type: String, required: true, unique: true },
  project: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  itemType: { type: mongoose.Schema.Types.ObjectId, ref: 'ItemType', required: true },
  vendor: { type: mongoose.Schema.Types.ObjectId, ref: 'Vendor', required: true },
  communicationPolicy: { type: mongoose.Schema.Types.ObjectId, ref: 'CommunicationPolicy' },
  spaceType: { type: mongoose.Schema.Types.ObjectId, ref: 'SpaceType' },
  status: { type: String, enum: ['active', 'inactive', 'provisioning', 'error'], default: 'provisioning' },
  certificate: {
    certificateArn: String,
    certificateId: String,
    publicKey: String,
    privateKey: String
  },
  firmware: {
    version: String,
    downloadUrl: String,
    checksum: String
  },
  location: {
    latitude: Number,
    longitude: Number,
    lastUpdated: { type: Date, default: Date.now }
  },
  createdAt: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now }
});

const otpSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  otp: { type: String, required: true },
  action: { type: String, enum: ['create_device', 'delete_device', 'provision_device'], required: true },
  deviceData: mongoose.Schema.Types.Mixed,
  expiresAt: { type: Date, default: Date.now, expires: 300 },
  used: { type: Boolean, default: false }
});

// Models
const User = mongoose.model('User', userSchema);
const Project = mongoose.model('Project', projectSchema);
const Vendor = mongoose.model('Vendor', vendorSchema);
const Parameter = mongoose.model('Parameter', parameterSchema);
const ItemType = mongoose.model('ItemType', itemTypeSchema);
const MessagingPolicy = mongoose.model('MessagingPolicy', messagingPolicySchema);
const CommunicationPolicy = mongoose.model('CommunicationPolicy', communicationPolicySchema);
const SpaceType = mongoose.model('SpaceType', spaceTypeSchema);
const Device = mongoose.model('Device', deviceSchema);
const OTP = mongoose.model('OTP', otpSchema);

// Email configuration (optional)
let transporter = null;
if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  transporter = nodemailer.createTransporter({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
  console.log("✅ Email service configured");
} else {
  console.log("⚠️  Email credentials not provided. Email features will be disabled.");
}

// Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

// Utility Functions
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const sendOTPEmail = async (email, otp, action, deviceName) => {
  if (!transporter) {
    console.log(`📧 OTP would be sent to ${email}: ${otp} (Email service disabled)`);
    return;
  }

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: `IoT Device ${action} - OTP Verification`,
    html: `
      <h2>Device ${action} Verification</h2>
      <p>Someone is attempting to ${action} device: <strong>${deviceName}</strong></p>
      <p>Your OTP is: <strong>${otp}</strong></p>
      <p>This OTP will expire in 5 minutes.</p>
      <p>If you didn't initiate this action, please contact your administrator.</p>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`📧 OTP sent to ${email}`);
  } catch (error) {
    console.error('Email send error:', error);
    throw error;
  }
};

const generateDeviceId = () => {
  return 'IOT_' + crypto.randomBytes(8).toString('hex').toUpperCase();
};

// AWS IoT functions (with fallback)
const createAWSIoTCertificate = async () => {
  if (!process.env.AWS_ACCESS_KEY_ID) {
    // Mock certificate for demo
    return {
      certificateArn: `arn:aws:iot:ap-south-1:123456789012:cert/${crypto.randomUUID()}`,
      certificateId: crypto.randomUUID(),
      publicKey: 'MOCK_PUBLIC_KEY',
      privateKey: 'MOCK_PRIVATE_KEY',
      certificatePem: 'MOCK_CERTIFICATE_PEM'
    };
  }

  try {
    const iot = new AWS.Iot();
    const params = { setAsActive: true };
    const result = await iot.createKeysAndCertificate(params).promise();

    return {
      certificateArn: result.certificateArn,
      certificateId: result.certificateId,
      publicKey: result.keyPair.PublicKey,
      privateKey: result.keyPair.PrivateKey,
      certificatePem: result.certificatePem
    };
  } catch (error) {
    console.error('Error creating AWS IoT certificate:', error);
    throw error;
  }
};

const createAWSIoTThing = async (deviceId, certificateArn) => {
  if (!process.env.AWS_ACCESS_KEY_ID) {
    console.log(`🔧 Mock AWS IoT Thing created for ${deviceId}`);
    return;
  }

  try {
    const iot = new AWS.Iot();
    
    // Create thing
    const thingParams = { thingName: deviceId };
    await iot.createThing(thingParams).promise();

    // Create policy
    const policyDocument = {
      Version: '2012-10-17',
      Statement: [{
        Effect: 'Allow',
        Action: ['iot:Connect', 'iot:Publish', 'iot:Subscribe', 'iot:Receive'],
        Resource: `arn:aws:iot:${AWS.config.region}:*:*`
      }]
    };

    const policyParams = {
      policyName: `${deviceId}_Policy`,
      policyDocument: JSON.stringify(policyDocument)
    };
    await iot.createPolicy(policyParams).promise();

    // Attach policy to certificate
    await iot.attachPolicy({
      policyName: `${deviceId}_Policy`,
      target: certificateArn
    }).promise();

    // Attach certificate to thing
    await iot.attachThingPrincipal({
      thingName: deviceId,
      principal: certificateArn
    }).promise();

  } catch (error) {
    console.error('Error creating AWS IoT Thing:', error);
    throw error;
  }
};

const generateFirmware = async (device) => {
  const firmwareVersion = `v1.0.${Date.now()}`;
  const checksum = crypto.createHash('sha256').update(device.deviceId + firmwareVersion).digest('hex');

  return {
    version: firmwareVersion,
    downloadUrl: `https://firmware.example.com/${device.deviceId}/${firmwareVersion}.bin`,
    checksum: checksum
  };
};

// Root route - serve the HTML file
app.get('/', (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  
  // Check if index.html exists, if not send a simple response
  const fs = require('fs');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.json({
      message: 'IoT Device Management API Server',
      status: 'running',
      endpoints: {
        auth: '/api/auth/login, /api/auth/register',
        vendors: '/api/vendors',
        parameters: '/api/parameters',
        projects: '/api/projects',
        devices: '/api/devices'
      }
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    services: {
      mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
      email: transporter ? 'configured' : 'disabled',
      aws: process.env.AWS_ACCESS_KEY_ID ? 'configured' : 'disabled'
    }
  });
});

// Authentication Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ message: 'Username or email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      email,
      password: hashedPassword,
      role: role || 'user'
    });

    await user.save();
    console.log(`✅ New user registered: ${username} (${role || 'user'})`);
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(400).json({ message: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }

    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '24h' }
    );

    console.log(`✅ User logged in: ${username} (${user.role})`);
    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Project Routes
app.get('/api/projects', authenticateToken, async (req, res) => {
  try {
    const projects = await Project.find().populate('owner', 'username email');
    res.json(projects);
  } catch (error) {
    console.error('Projects fetch error:', error);
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/projects', authenticateToken, async (req, res) => {
  try {
    const project = new Project({
      ...req.body,
      owner: req.user.id
    });
    await project.save();
    
    // Populate the owner before sending response
    await project.populate('owner', 'username email');
    
    console.log(`✅ Project created: ${project.name} by ${req.user.username}`);
    res.status(201).json(project);
  } catch (error) {
    console.error('Project creation error:', error);
    res.status(400).json({ message: error.message });
  }
});

app.delete('/api/projects/:id', authenticateToken, async (req, res) => {
  try {
    const project = await Project.findByIdAndDelete(req.params.id);
    if (!project) {
      return res.status(404).json({ message: 'Project not found' });
    }
    console.log(`✅ Project deleted: ${project.name}`);
    res.json({ message: 'Project deleted successfully' });
  } catch (error) {
    console.error('Project deletion error:', error);
    res.status(500).json({ message: error.message });
  }
});

// Vendor Routes
app.get('/api/vendors', authenticateToken, async (req, res) => {
  try {
    const vendors = await Vendor.find().sort({ createdAt: -1 });
    res.json(vendors);
  } catch (error) {
    console.error('Vendors fetch error:', error);
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/vendors', authenticateToken, async (req, res) => {
  try {
    const vendor = new Vendor(req.body);
    await vendor.save();
    console.log(`✅ Vendor created: ${vendor.name}`);
    res.status(201).json(vendor);
  } catch (error) {
    console.error('Vendor creation error:', error);
    res.status(400).json({ message: error.message });
  }
});

app.delete('/api/vendors/:id', authenticateToken, async (req, res) => {
  try {
    const vendor = await Vendor.findByIdAndDelete(req.params.id);
    if (!vendor) {
      return res.status(404).json({ message: 'Vendor not found' });
    }
    console.log(`✅ Vendor deleted: ${vendor.name}`);
    res.json({ message: 'Vendor deleted successfully' });
  } catch (error) {
    console.error('Vendor deletion error:', error);
    res.status(500).json({ message: error.message });
  }
});

// Parameter Routes
app.get('/api/parameters', authenticateToken, async (req, res) => {
  try {
    const parameters = await Parameter.find().sort({ createdAt: -1 });
    res.json(parameters);
  } catch (error) {
    console.error('Parameters fetch error:', error);
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/parameters', authenticateToken, async (req, res) => {
  try {
    const parameter = new Parameter(req.body);
    await parameter.save();
    console.log(`✅ Parameter created: ${parameter.name}`);
    res.status(201).json(parameter);
  } catch (error) {
    console.error('Parameter creation error:', error);
    res.status(400).json({ message: error.message });
  }
});

app.delete('/api/parameters/:id', authenticateToken, async (req, res) => {
  try {
    const parameter = await Parameter.findByIdAndDelete(req.params.id);
    if (!parameter) {
      return res.status(404).json({ message: 'Parameter not found' });
    }
    console.log(`✅ Parameter deleted: ${parameter.name}`);
    res.json({ message: 'Parameter deleted successfully' });
  } catch (error) {
    console.error('Parameter deletion error:', error);
    res.status(500).json({ message: error.message });
  }
});

// Item Type Routes
app.get('/api/item-types', authenticateToken, async (req, res) => {
  try {
    const itemTypes = await ItemType.find()
      .populate('parameters', 'name dataType unit')
      .populate('vendor', 'name')
      .sort({ createdAt: -1 });
    res.json(itemTypes);
  } catch (error) {
    console.error('Item types fetch error:', error);
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/item-types', authenticateToken, async (req, res) => {
  try {
    const itemType = new ItemType(req.body);
    await itemType.save();
    await itemType.populate(['parameters', 'vendor']);
    console.log(`✅ Item type created: ${itemType.name}`);
    res.status(201).json(itemType);
  } catch (error) {
    console.error('Item type creation error:', error);
    res.status(400).json({ message: error.message });
  }
});

app.delete('/api/item-types/:id', authenticateToken, async (req, res) => {
  try {
    const itemType = await ItemType.findByIdAndDelete(req.params.id);
    if (!itemType) {
      return res.status(404).json({ message: 'Item type not found' });
    }
    console.log(`✅ Item type deleted: ${itemType.name}`);
    res.json({ message: 'Item type deleted successfully' });
  } catch (error) {
    console.error('Item type deletion error:', error);
    res.status(500).json({ message: error.message });
  }
});

// Messaging Policy Routes
app.get('/api/messaging-policies', authenticateToken, async (req, res) => {
  try {
    const policies = await MessagingPolicy.find().sort({ createdAt: -1 });
    res.json(policies);
  } catch (error) {
    console.error('Messaging policies fetch error:', error);
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/messaging-policies', authenticateToken, async (req, res) => {
  try {
    const policy = new MessagingPolicy(req.body);
    await policy.save();
    console.log(`✅ Messaging policy created: ${policy.name}`);
    res.status(201).json(policy);
  } catch (error) {
    console.error('Messaging policy creation error:', error);
    res.status(400).json({ message: error.message });
  }
});

app.delete('/api/messaging-policies/:id', authenticateToken, async (req, res) => {
  try {
    const policy = await MessagingPolicy.findByIdAndDelete(req.params.id);
    if (!policy) {
      return res.status(404).json({ message: 'Messaging policy not found' });
    }
    console.log(`✅ Messaging policy deleted: ${policy.name}`);
    res.json({ message: 'Messaging policy deleted successfully' });
  } catch (error) {
    console.error('Messaging policy deletion error:', error);
    res.status(500).json({ message: error.message });
  }
});

// Communication Policy Routes
app.get('/api/communication-policies', authenticateToken, async (req, res) => {
  try {
    const policies = await CommunicationPolicy.find()
      .populate('messagingPolicies', 'name protocol')
      .sort({ createdAt: -1 });
    res.json(policies);
  } catch (error) {
    console.error('Communication policies fetch error:', error);
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/communication-policies', authenticateToken, async (req, res) => {
  try {
    const policy = new CommunicationPolicy(req.body);
    await policy.save();
    await policy.populate('messagingPolicies', 'name protocol');
    console.log(`✅ Communication policy created: ${policy.name}`);
    res.status(201).json(policy);
  } catch (error) {
    console.error('Communication policy creation error:', error);
    res.status(400).json({ message: error.message });
  }
});

app.delete('/api/communication-policies/:id', authenticateToken, async (req, res) => {
  try {
    const policy = await CommunicationPolicy.findByIdAndDelete(req.params.id);
    if (!policy) {
      return res.status(404).json({ message: 'Communication policy not found' });
    }
    console.log(`✅ Communication policy deleted: ${policy.name}`);
    res.json({ message: 'Communication policy deleted successfully' });
  } catch (error) {
    console.error('Communication policy deletion error:', error);
    res.status(500).json({ message: error.message });
  }
});

// Space Type Routes
app.get('/api/space-types', authenticateToken, async (req, res) => {
  try {
    const spaceTypes = await SpaceType.find().sort({ createdAt: -1 });
    res.json(spaceTypes);
  } catch (error) {
    console.error('Space types fetch error:', error);
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/space-types', authenticateToken, async (req, res) => {
  try {
    const spaceType = new SpaceType(req.body);
    await spaceType.save();
    console.log(`✅ Space type created: ${spaceType.name}`);
    res.status(201).json(spaceType);
  } catch (error) {
    console.error('Space type creation error:', error);
    res.status(400).json({ message: error.message });
  }
});

app.delete('/api/space-types/:id', authenticateToken, async (req, res) => {
  try {
    const spaceType = await SpaceType.findByIdAndDelete(req.params.id);
    if (!spaceType) {
      return res.status(404).json({ message: 'Space type not found' });
    }
    console.log(`✅ Space type deleted: ${spaceType.name}`);
    res.json({ message: 'Space type deleted successfully' });
  } catch (error) {
    console.error('Space type deletion error:', error);
    res.status(500).json({ message: error.message });
  }
});

// Device Routes
app.get('/api/devices', authenticateToken, async (req, res) => {
  try {
    const devices = await Device.find()
      .populate('project', 'name description')
      .populate('itemType', 'name description')
      .populate('vendor', 'name')
      .populate('communicationPolicy', 'name')
      .populate('spaceType', 'name')
      .sort({ createdAt: -1 });
    res.json(devices);
  } catch (error) {
    console.error('Devices fetch error:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get individual device
app.get('/api/devices/:id', authenticateToken, async (req, res) => {
  try {
    const device = await Device.findById(req.params.id)
      .populate('project', 'name description')
      .populate('itemType', 'name description')
      .populate('vendor', 'name contactEmail')
      .populate('communicationPolicy', 'name description')
      .populate('spaceType', 'name description');

    if (!device) {
      return res.status(404).json({ message: 'Device not found' });
    }

    res.json(device);
  } catch (error) {
    console.error('Device fetch error:', error);
    res.status(500).json({ message: error.message });
  }
});

// Device creation with OTP
app.post('/api/devices/create-otp', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const otp = generateOTP();
    const user = await User.findById(req.user.id);

    const otpRecord = new OTP({
      userId: req.user.id,
      otp,
      action: 'create_device',
      deviceData: req.body
    });

    await otpRecord.save();
    
    if (transporter) {
      await sendOTPEmail(user.email, otp, 'CREATE', req.body.name);
    }

    console.log(`📧 OTP created for device creation: ${req.body.name}`);
    res.json({ message: 'OTP sent to admin email', otpId: otpRecord._id });
  } catch (error) {
    console.error('OTP creation error:', error);
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/devices/verify-create', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { otpId, otp } = req.body;

    const otpRecord = await OTP.findOne({
      _id: otpId,
      otp,
      action: 'create_device',
      used: false
    });

    if (!otpRecord) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const deviceData = otpRecord.deviceData;
    const deviceId = generateDeviceId();

    // Create AWS IoT certificate (or mock)
    const certificate = await createAWSIoTCertificate();

    // Generate firmware
    const firmwareData = await generateFirmware({ deviceId });

    const device = new Device({
      ...deviceData,
      deviceId,
      certificate,
      firmware: firmwareData
    });

    await device.save();

    // Create AWS IoT Thing (or mock)
    await createAWSIoTThing(deviceId, certificate.certificateArn);

    // Mark OTP as used
    otpRecord.used = true;
    await otpRecord.save();

    // Populate device data before sending response
    await device.populate(['project', 'itemType', 'vendor', 'communicationPolicy', 'spaceType']);

    console.log(`✅ Device created: ${device.name} (${deviceId})`);
    res.status(201).json(device);
  } catch (error) {
    console.error('Device creation error:', error);
    res.status(400).json({ message: error.message });
  }
});

// Multi-device creation
app.post('/api/devices/multi-create-otp', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { devices } = req.body;
    const otp = generateOTP();
    const user = await User.findById(req.user.id);

    const otpRecord = new OTP({
      userId: req.user.id,
      otp,
      action: 'create_device',
      deviceData: { devices, isMultiple: true }
    });

    await otpRecord.save();
    
    if (transporter) {
      await sendOTPEmail(user.email, otp, 'CREATE MULTIPLE', `${devices.length} devices`);
    }

    console.log(`📧 OTP created for multi-device creation: ${devices.length} devices`);
    res.json({ message: 'OTP sent to admin email', otpId: otpRecord._id });
  } catch (error) {
    console.error('Multi-device OTP creation error:', error);
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/devices/verify-multi-create', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { otpId, otp } = req.body;

    const otpRecord = await OTP.findOne({
      _id: otpId,
      otp,
      action: 'create_device',
      used: false
    });

    if (!otpRecord) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const { devices } = otpRecord.deviceData;
    const createdDevices = [];

    for (const deviceData of devices) {
      const deviceId = generateDeviceId();
      const certificate = await createAWSIoTCertificate();
      const firmwareData = await generateFirmware({ deviceId });

      const device = new Device({
        ...deviceData,
        deviceId,
        certificate,
        firmware: firmwareData
      });

      await device.save();
      await createAWSIoTThing(deviceId, certificate.certificateArn);
      await device.populate(['project', 'itemType', 'vendor']);

      createdDevices.push(device);
    }

    otpRecord.used = true;
    await otpRecord.save();

    console.log(`✅ ${createdDevices.length} devices created successfully`);
    res.status(201).json(createdDevices);
  } catch (error) {
    console.error('Multi-device creation error:', error);
    res.status(400).json({ message: error.message });
  }
});

// Device deletion with OTP
app.delete('/api/devices/:id/delete-otp', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const device = await Device.findById(req.params.id);
    if (!device) {
      return res.status(404).json({ message: 'Device not found' });
    }

    const otp = generateOTP();
    const user = await User.findById(req.user.id);

    const otpRecord = new OTP({
      userId: req.user.id,
      otp,
      action: 'delete_device',
      deviceData: { deviceId: req.params.id }
    });

    await otpRecord.save();
    
    if (transporter) {
      await sendOTPEmail(user.email, otp, 'DELETE', device.name);
    }

    console.log(`📧 OTP created for device deletion: ${device.name}`);
    res.json({ message: 'OTP sent to admin email', otpId: otpRecord._id });
  } catch (error) {
    console.error('Device deletion OTP error:', error);
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/devices/verify-delete', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { otpId, otp } = req.body;

    const otpRecord = await OTP.findOne({
      _id: otpId,
      otp,
      action: 'delete_device',
      used: false
    });

    if (!otpRecord) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const device = await Device.findById(otpRecord.deviceData.deviceId);
    if (!device) {
      return res.status(404).json({ message: 'Device not found' });
    }

    // Delete from AWS IoT Core (if configured)
    if (process.env.AWS_ACCESS_KEY_ID) {
      try {
        const iot = new AWS.Iot();
        await iot.deleteThing({ thingName: device.deviceId }).promise();
        await iot.deletePolicy({ policyName: `${device.deviceId}_Policy` }).promise();
        await iot.deleteCertificate({
          certificateId: device.certificate.certificateId,
          forceDelete: true
        }).promise();
      } catch (awsError) {
        console.error('AWS deletion error:', awsError);
      }
    }

    await Device.findByIdAndDelete(otpRecord.deviceData.deviceId);

    otpRecord.used = true;
    await otpRecord.save();

    console.log(`✅ Device deleted: ${device.name}`);
    res.json({ message: 'Device deleted successfully' });
  } catch (error) {
    console.error('Device deletion error:', error);
    res.status(500).json({ message: error.message });
  }
});

// Device location update
app.put('/api/devices/:id/location', authenticateToken, async (req, res) => {
  try {
    const { latitude, longitude } = req.body;
    const device = await Device.findByIdAndUpdate(
      req.params.id,
      {
        'location.latitude': latitude,
        'location.longitude': longitude,
        'location.lastUpdated': new Date(),
        lastSeen: new Date()
      },
      { new: true }
    );

    if (!device) {
      return res.status(404).json({ message: 'Device not found' });
    }

    res.json(device);
  } catch (error) {
    console.error('Device location update error:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get device locations for map
app.get('/api/devices/locations', authenticateToken, async (req, res) => {
  try {
    const devices = await Device.find({
      'location.latitude': { $exists: true },
      'location.longitude': { $exists: true }
    })
      .select('name deviceId location status itemType')
      .populate('itemType', 'name');

    res.json(devices);
  } catch (error) {
    console.error('Device locations fetch error:', error);
    res.status(500).json({ message: error.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 404 handler for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({
    message: 'API endpoint not found',
    availableEndpoints: [
      'GET /api/vendors',
      'GET /api/parameters',
      'GET /api/projects',
      'GET /api/devices',
      'POST /api/auth/login',
      'POST /api/auth/register'
    ]
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  mongoose.connection.close(() => {
    console.log('MongoDB connection closed');
    process.exit(0);
  });
});

const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🚀 IoT Device Management Server`);
  console.log(`📡 Server running on: http://localhost:${PORT}`);
  console.log(`🗄️  Database: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Connecting...'}`);
  console.log(`📧 Email: ${transporter ? 'Configured' : 'Disabled'}`);
  console.log(`☁️  AWS: ${process.env.AWS_ACCESS_KEY_ID ? 'Configured' : 'Disabled (Mock mode)'}`);
  console.log(`\n🔗 API Endpoints:`);
  console.log(`   • Auth: http://3.7.165.153:${PORT}/api/auth/login`);
  console.log(`   • Vendors: http://3.7.165.153:${PORT}/api/vendors`);
  console.log(`   • Devices: http://3.7.165.153:${PORT}/api/devices`);
  console.log(`   • Health: http://3.7.165.153:${PORT}/health`);
  console.log(`\n💡 Place your HTML file in 'public/index.html' or access the API directly\n`);
});

// Handle server errors
server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`❌ Port ${PORT} is already in use. Please try a different port.`);
    console.log(`💡 You can set a different port: PORT=3000 npm start`);
  } else {
    console.error('Server error:', err);
  }
  process.exit(1);
});
