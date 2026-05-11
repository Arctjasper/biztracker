const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));

const JWT_SECRET = process.env.JWT_SECRET || 'quicktracker-secret-2024';
const MONGODB_URI = process.env.MONGODB_URI;

// ── MONGODB CONNECTION ──
let db;
async function connectDB() {
  try {
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    db = client.db('quicktracker');
    console.log('✅ MongoDB connected!');
  } catch(e) {
    console.error('MongoDB connection error:', e.message);
    setTimeout(connectDB, 5000);
  }
}

const users = () => db.collection('users');
const businesses = () => db.collection('businesses');

// ── EMAIL ──
const sendResetEmail = async (email, name, code) => {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.log(`Reset code for ${email}: ${code}`);
    return;
  }
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
  });
  await transporter.sendMail({
    from: `"Quick Tracker" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: '🔐 Quick Tracker - Password Reset Code',
    html: `
      <div style="font-family:monospace;background:#07090f;color:#e2e8f0;padding:40px;max-width:500px;margin:0 auto;border-radius:12px;">
        <h2 style="color:#3b82f6">Quick Tracker 🔑</h2>
        <p>Hi <b>${name}</b>, your password reset code is:</p>
        <div style="background:#1c2333;border:2px solid #3b82f6;border-radius:8px;padding:24px;text-align:center;margin:20px 0;">
          <div style="font-size:40px;font-weight:bold;color:#3b82f6;letter-spacing:12px">${code}</div>
        </div>
        <p style="color:#64748b;font-size:12px">This code expires in 15 minutes.</p>
      </div>
    `
  });
};

// ── AUTH MIDDLEWARE ──
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
};

// ── HEALTH ──
app.get('/', async (req, res) => {
  const count = db ? await users().countDocuments() : 0;
  res.json({ status: 'ok', app: 'Quick Tracker', users: count, db: db ? 'connected' : 'disconnected' });
});
app.get('/api/health', async (req, res) => {
  const count = db ? await users().countDocuments() : 0;
  res.json({ status: 'ok', app: 'Quick Tracker', users: count, db: db ? 'connected' : 'disconnected' });
});

// ── REGISTER ──
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, businessName, pin } = req.body;
    if (!name || !email || !password || !businessName)
      return res.status(400).json({ error: 'All fields required' });
    const existing = await users().findOne({ email: email.toLowerCase().trim() });
    if (existing) return res.status(400).json({ error: 'Email already registered' });
    const userId = new ObjectId().toString();
    const user = {
      _id: userId, id: userId, name,
      email: email.toLowerCase().trim(),
      password: await bcrypt.hash(password, 10),
      pin: pin ? await bcrypt.hash(pin, 10) : null,
      role: 'owner', createdAt: new Date().toISOString(),
      businessId: userId
    };
    await users().insertOne(user);
    await businesses().insertOne({
      _id: userId, id: userId,
      businessName, bankName: 'Bank Account',
      vatEnabled: false, bank: 0, cashOnHand: 0,
      netIncome: 0, netIncomeMonth: '',
      revenues: [], expenses: [], sales: [],
      payables: [], receivables: [],
      vendors: [], partners: [],
      savedSaleItems: [], savedExpenseItems: [],
      teamMembers: [], users: [userId]
    });
    const token = jwt.sign({ userId, businessId: userId }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: userId, name, email: user.email, role: 'owner' } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── LOGIN ──
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const user = await users().findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.status(401).json({ error: 'Email not found. Please register first.' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Incorrect password.' });
    const token = jwt.sign({ userId: user.id, businessId: user.businessId }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── FORGOT PASSWORD ──
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    const user = await users().findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.status(404).json({ error: 'Email not found. Use the email you registered with.' });
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await users().updateOne(
      { email: email.toLowerCase().trim() },
      { $set: { resetCode: code, resetExpires: Date.now() + 15 * 60 * 1000 } }
    );
    res.json({ success: true, message: 'Reset code sent to your email!' });
    sendResetEmail(user.email, user.name, code).catch(e => console.error('Email error:', e.message));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── RESET PASSWORD ──
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    const user = await users().findOne({ email: email?.toLowerCase().trim() });
    if (!user) return res.status(404).json({ error: 'Email not found' });
    if (!user.resetCode || user.resetCode !== code)
      return res.status(400).json({ error: 'Invalid reset code' });
    if (Date.now() > user.resetExpires)
      return res.status(400).json({ error: 'Code expired. Request a new one.' });
    await users().updateOne(
      { email: email.toLowerCase().trim() },
      { $set: { password: await bcrypt.hash(newPassword, 10) }, $unset: { resetCode: '', resetExpires: '' } }
    );
    res.json({ success: true, message: 'Password reset successfully!' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── CHANGE PASSWORD ──
app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await users().findOne({ id: req.user.userId });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!await bcrypt.compare(currentPassword, user.password))
      return res.status(401).json({ error: 'Current password incorrect' });
    await users().updateOne({ id: req.user.userId }, { $set: { password: await bcrypt.hash(newPassword, 10) } });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── CHANGE PIN ──
app.post('/api/auth/change-pin', auth, async (req, res) => {
  try {
    const { pin } = req.body;
    await users().updateOne({ id: req.user.userId }, { $set: { pin: await bcrypt.hash(pin, 10) } });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── ADD MEMBER ──
app.post('/api/auth/add-member', auth, async (req, res) => {
  try {
    const { name, email, password, role, employeeNo, department, dateOfJoining } = req.body;
    const requester = await users().findOne({ id: req.user.userId });
    if (requester?.role !== 'owner') return res.status(403).json({ error: 'Only owner can add members' });
    if (await users().findOne({ email: email?.toLowerCase() }))
      return res.status(400).json({ error: 'Email already registered' });
    const userId = new ObjectId().toString();
    const member = {
      _id: userId, id: userId, name,
      email: email.toLowerCase(),
      password: await bcrypt.hash(password, 10),
      role: role || 'staff', businessId: req.user.businessId,
      employeeNo, department, dateOfJoining,
      createdAt: new Date().toISOString()
    };
    await users().insertOne(member);
    const memberInfo = { id: userId, name, email: member.email, role: member.role, employeeNo, department, dateOfJoining };
    await businesses().updateOne(
      { id: req.user.businessId },
      { $push: { users: userId, teamMembers: memberInfo } }
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── BUSINESS DATA ──
app.get('/api/business', auth, async (req, res) => {
  try {
    const biz = await businesses().findOne({ id: req.user.businessId });
    if (!biz) return res.status(404).json({ error: 'Business not found' });
    res.json(biz);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/business', auth, async (req, res) => {
  try {
    await businesses().updateOne(
      { id: req.user.businessId },
      { $set: req.body },
      { upsert: true }
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── AI ──
app.post('/api/ai/chat', auth, async (req, res) => {
  try {
    const { Anthropic } = require('@anthropic-ai/sdk');
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const { messages, system } = req.body;
    const response = await client.messages.create({ model: 'claude-sonnet-4-20250514', max_tokens: 1000, system, messages });
    res.json({ content: response.content });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

const PORT = process.env.PORT || 5000;

// Connect to MongoDB then start server
connectDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => console.log(`✅ Quick Tracker running on port ${PORT}`));
});
