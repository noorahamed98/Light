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
app.use(cors({
  origin: "*", // Allow all origins (change to your frontend URL in production)
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Add this after your other middleware
app.use(express.static('public'));

// Modify your root route to serve the HTML file instead of JSON
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Configure AWS
AWS.config.update({
  region: process.env.AWS_REGION || 'ap-south-1',
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});

const iot = new AWS.Iot();
const iotData = new AWS.IotData({
  endpoint: process.env.AWS_IOT_ENDPOINT
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/iot_management', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => {
  console.log("✅ MongoDB Connected");
})
.catch((err) => {
  console.error("MongoDB connection error:", err);
});

// Schemas
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

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

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

  await transporter.sendMail(mailOptions);
};

const generateDeviceId = () => {
  return 'IOT_' + crypto.randomBytes(8).toString('hex').toUpperCase();
};

const createAWSIoTCertificate = async () => {
  try {
    const params = {
      setAsActive: true
    };

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
  try {
    const thingParams = {
      thingName: deviceId
    };
    await iot.createThing(thingParams).promise();

    const policyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: [
            'iot:Connect',
            'iot:Publish',
            'iot:Subscribe',
            'iot:Receive'
          ],
          Resource: `arn:aws:iot:${AWS.config.region}:*:*`
        }
      ]
    };

    const policyParams = {
      policyName: `${deviceId}_Policy`,
      policyDocument: JSON.stringify(policyDocument)
    };
    await iot.createPolicy(policyParams).promise();

    const attachPolicyParams = {
      policyName: `${deviceId}_Policy`,
      target: certificateArn
    };
    await iot.attachPolicy(attachPolicyParams).promise();

    const attachThingParams = {
      thingName: deviceId,
      principal: certificateArn
    };
    await iot.attachThingPrincipal(attachThingParams).promise();

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

// Add a root route
app.get('/', (req, res) => {
  res.json({
    message: 'IoT Management API Server is running!',
    version: '1.0.0',
    endpoints: {
      auth: '/api/auth',
      projects: '/api/projects',
      devices: '/api/devices',
      vendors: '/api/vendors'
    }
  });
});

// Authentication Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      email,
      password: hashedPassword,
      role
    });

    await user.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '24h' }
    );

    res.json({ token, user: { id: user._id, username: user.username, role: user.role } });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Project Routes
app.get('/api/projects', authenticateToken, async (req, res) => {
  try {
    const projects = await Project.find().populate('owner', 'username');
    res.json(projects);
  } catch (error) {
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
    res.status(201).json(project);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Vendor Routes
app.get('/api/vendors', authenticateToken, async (req, res) => {
  try {
    const vendors = await Vendor.find();
    res.json(vendors);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/vendors', authenticateToken, async (req, res) => {
  try {
    const vendor = new Vendor(req.body);
    await vendor.save();
    res.status(201).json(vendor);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Parameter Routes
app.get('/api/parameters', authenticateToken, async (req, res) => {
  try {
    const parameters = await Parameter.find();
    res.json(parameters);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/parameters', authenticateToken, async (req, res) => {
  try {
    const parameter = new Parameter(req.body);
    await parameter.save();
    res.status(201).json(parameter);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Item Type Routes
app.get('/api/item-types', authenticateToken, async (req, res) => {
  try {
    const itemTypes = await ItemType.find().populate('parameters vendor');
    res.json(itemTypes);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/item-types', authenticateToken, async (req, res) => {
  try {
    const itemType = new ItemType(req.body);
    await itemType.save();
    res.status(201).json(itemType);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Messaging Policy Routes
app.get('/api/messaging-policies', authenticateToken, async (req, res) => {
  try {
    const policies = await MessagingPolicy.find();
    res.json(policies);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/messaging-policies', authenticateToken, async (req, res) => {
  try {
    const policy = new MessagingPolicy(req.body);
    await policy.save();
    res.status(201).json(policy);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Communication Policy Routes
app.get('/api/communication-policies', authenticateToken, async (req, res) => {
  try {
    const policies = await CommunicationPolicy.find().populate('messagingPolicies');
    res.json(policies);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/communication-policies', authenticateToken, async (req, res) => {
  try {
    const policy = new CommunicationPolicy(req.body);
    await policy.save();
    res.status(201).json(policy);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Space Type Routes
app.get('/api/space-types', authenticateToken, async (req, res) => {
  try {
    const spaceTypes = await SpaceType.find();
    res.json(spaceTypes);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/space-types', authenticateToken, async (req, res) => {
  try {
    const spaceType = new SpaceType(req.body);
    await spaceType.save();
    res.status(201).json(spaceType);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Device Routes
app.get('/api/devices', authenticateToken, async (req, res) => {
  try {
    const devices = await Device.find()
      .populate('project itemType vendor communicationPolicy spaceType');
    res.json(devices);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

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
    await sendOTPEmail(user.email, otp, 'CREATE', req.body.name);

    res.json({ message: 'OTP sent to admin email', otpId: otpRecord._id });
  } catch (error) {
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

    // Create AWS IoT certificate
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

    // Create AWS IoT Thing
    await createAWSIoTThing(deviceId, certificate.certificateArn);

    // Mark OTP as used
    otpRecord.used = true;
    await otpRecord.save();

    res.status(201).json(device);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

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
    await sendOTPEmail(user.email, otp, 'CREATE MULTIPLE', `${devices.length} devices`);

    res.json({ message: 'OTP sent to admin email', otpId: otpRecord._id });
  } catch (error) {
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

      createdDevices.push(device);
    }

    otpRecord.used = true;
    await otpRecord.save();

    res.status(201).json(createdDevices);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

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
    await sendOTPEmail(user.email, otp, 'DELETE', device.name);

    res.json({ message: 'OTP sent to admin email', otpId: otpRecord._id });
  } catch (error) {
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

    // Delete from AWS IoT Core
    try {
      await iot.deleteThing({ thingName: device.deviceId }).promise();
      await iot.deletePolicy({ policyName: `${device.deviceId}_Policy` }).promise();
      await iot.deleteCertificate({
        certificateId: device.certificate.certificateId,
        forceDelete: true
      }).promise();
    } catch (awsError) {
      console.error('AWS deletion error:', awsError);
    }

    await Device.findByIdAndDelete(otpRecord.deviceData.deviceId);

    otpRecord.used = true;
    await otpRecord.save();

    res.json({ message: 'Device deleted successfully' });
  } catch (error) {
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
    res.status(500).json({ message: error.message });
  }
});

// Get device locations for map
app.get('/api/devices/locations', authenticateToken, async (req, res) => {
  try {
    const devices = await Device.find({
      'location.latitude': { $exists: true },
      'location.longitude': { $exists: true }
    }).select('name deviceId location status itemType')
    .populate('itemType', 'name');

    res.json(devices);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
