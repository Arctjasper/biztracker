const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

const app = express();

// Allow all origins for mobile app
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));

const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'db.json');
const JWT_SECRET = process.env.JWT_SECRET || 'quicktracker-secret-2024';

// ── DATA HELPERS ──
const loadDB = () => {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify({ users: [], businesses: {} }));
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
};
const saveDB = (db) => fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));

// ── EMAIL ──
const sendResetEmail = async (email, name, code) => {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) return;
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
        <div style="background:#1c2333;border:1px solid #3b82f6;border-radius:8px;padding:20px;text-align:center;margin:20px 0;">
          <div style="font-size:36px;font-weight:bold;color:#3b82f6;letter-spacing:10px">${code}</div>
        </div>
        <p style="color:#64748b;font-size:12px">Expires in 15 minutes. If you did not request this, ignore this email.</p>
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

// ── HEALTH CHECK ──
app.get('/', (req, res) => res.json({ status: 'ok', app: 'Quick Tracker', version: '1.0.0' }));
app.get('/api/health', (req, res) => res.json({ status: 'ok', app: 'Quick Tracker' }));

// ── REGISTER ──
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, businessName, pin } = req.body;
    if (!name || !email || !password || !businessName)
      return res.status(400).json({ error: 'All fields required' });
    const db = loadDB();
    if (db.users.find(u => u.email === email.toLowerCase()))
      return res.status(400).json({ error: 'Email already registered' });
    const userId = Date.now().toString(36);
    const user = {
      id: userId, name, email: email.toLowerCase(),
      password: await bcrypt.hash(password, 10),
      pin: pin ? await bcrypt.hash(pin, 10) : null,
      role: 'owner', createdAt: new Date().toISOString(),
      businessId: userId
    };
    db.users.push(user);
    db.businesses[userId] = {
      businessName, bankName: 'Bank Account',
      vatEnabled: false, bank: 0, cashOnHand: 0,
      netIncome: 0, netIncomeMonth: '',
      revenues: [], expenses: [], sales: [],
      payables: [], receivables: [],
      vendors: [], partners: [],
      savedSaleItems: [], savedExpenseItems: [],
      teamMembers: [], users: [userId]
    };
    saveDB(db);
    const token = jwt.sign({ userId, businessId: userId }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: userId, name, email: user.email, role: 'owner' } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── LOGIN ──
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.email === email?.toLowerCase());
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (!await bcrypt.compare(password, user.password))
      return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ userId: user.id, businessId: user.businessId }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── FORGOT PASSWORD ──
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.email === email?.toLowerCase());
    if (!user) return res.status(404).json({ error: 'Email not found' });
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    user.resetCode = code;
    user.resetExpires = Date.now() + 15 * 60 * 1000;
    saveDB(db);
    // Send email async - don't wait for it to respond
    res.json({ success: true, message: 'Reset code sent to your email!' });
    // Send email after responding
    sendResetEmail(user.email, user.name, code).catch(e => console.error('Email error:', e));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── RESET PASSWORD ──
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.email === email?.toLowerCase());
    if (!user) return res.status(404).json({ error: 'Email not found' });
    if (!user.resetCode || user.resetCode !== code)
      return res.status(400).json({ error: 'Invalid reset code' });
    if (Date.now() > user.resetExpires)
      return res.status(400).json({ error: 'Code expired. Request a new one.' });
    user.password = await bcrypt.hash(newPassword, 10);
    delete user.resetCode;
    delete user.resetExpires;
    saveDB(db);
    res.json({ success: true, message: 'Password reset successfully!' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── CHANGE PASSWORD ──
app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.id === req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!await bcrypt.compare(currentPassword, user.password))
      return res.status(401).json({ error: 'Current password incorrect' });
    user.password = await bcrypt.hash(newPassword, 10);
    saveDB(db);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── CHANGE PIN ──
app.post('/api/auth/change-pin', auth, async (req, res) => {
  try {
    const { pin } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.id === req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.pin = await bcrypt.hash(pin, 10);
    saveDB(db);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── ADD MEMBER ──
app.post('/api/auth/add-member', auth, async (req, res) => {
  try {
    const { name, email, password, role, employeeNo, department, dateOfJoining } = req.body;
    const db = loadDB();
    const requester = db.users.find(u => u.id === req.user.userId);
    if (requester?.role !== 'owner') return res.status(403).json({ error: 'Only owner can add members' });
    if (db.users.find(u => u.email === email?.toLowerCase()))
      return res.status(400).json({ error: 'Email already registered' });
    const userId = Date.now().toString(36) + 'b';
    const member = {
      id: userId, name, email: email.toLowerCase(),
      password: await bcrypt.hash(password, 10),
      role: role || 'staff', businessId: req.user.businessId,
      employeeNo, department, dateOfJoining,
      createdAt: new Date().toISOString()
    };
    db.users.push(member);
    const biz = db.businesses[req.user.businessId];
    if (biz) {
      biz.users = biz.users || [];
      biz.users.push(userId);
      biz.teamMembers = biz.teamMembers || [];
      biz.teamMembers.push({ id: userId, name, email: member.email, role: member.role, employeeNo, department, dateOfJoining });
    }
    saveDB(db);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── BUSINESS DATA ──
app.get('/api/business', auth, (req, res) => {
  try {
    const db = loadDB();
    const biz = db.businesses[req.user.businessId];
    if (!biz) return res.status(404).json({ error: 'Business not found' });
    res.json(biz);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/business', auth, (req, res) => {
  try {
    const db = loadDB();
    db.businesses[req.user.businessId] = { ...db.businesses[req.user.businessId], ...req.body };
    saveDB(db);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── AI CHAT ──
app.post('/api/ai/chat', auth, async (req, res) => {
  try {
    const { Anthropic } = require('@anthropic-ai/sdk');
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const { messages, system } = req.body;
    const response = await client.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      system, messages
    });
    res.json({ content: response.content });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/ai/extract-pdf', auth, async (req, res) => {
  try {
    const { Anthropic } = require('@anthropic-ai/sdk');
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const { pdfBase64 } = req.body;
    const response = await client.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1500,
      messages: [{ role: 'user', content: [
        { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: pdfBase64 } },
        { type: 'text', text: 'Extract all financial transactions. Return ONLY a JSON array. Each item: {date:"DD/MM/YYYY",description:"string",amount:number}. No markdown.' }
      ]}]
    });
    const text = response.content.map(c => c.text || '').join('');
    const parsed = JSON.parse(text.replace(/```json|```/g, '').trim());
    res.json({ entries: parsed });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Use Render's PORT environment variable
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`✅ Quick Tracker running on port ${PORT}`));
